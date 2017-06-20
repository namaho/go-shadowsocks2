package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

var MaxTCPPort = 65536

type Config struct {
	ServerPort        int    `json:"server_port"`
	Password          string `json:"password"`
	UploadRateLimit   int    `json:"upload_rate_limit"`
	DownloadRateLimit int    `json:"download_rate_limit"`
	Method            string `json:"method"`
}

type Manager struct {
	sync.Mutex
	stats                map[string]int
	relays               map[string][]interface{}
	DownloadLimitBuckets map[string]interface{}
	UploadLimitBuckets   map[string]interface{}
	clientAddr           *net.UDPAddr
	serverAddr           *net.UDPAddr
	serverConn           *net.UDPConn
	listen               string
	excludeBlockPorts    []int
	blockPortRanges      [][]int
	blockList            []string
	blockPattern         string
	running              bool
	ctx                  *context.Context
}

func NewManager(ctx *context.Context) *Manager {

	return &Manager{
		stats:                make(map[string]int),
		relays:               make(map[string][]interface{}),
		DownloadLimitBuckets: make(map[string]interface{}),
		UploadLimitBuckets:   make(map[string]interface{}),
		clientAddr:           nil,
		serverAddr:           nil,
		serverConn:           nil,
		listen:               "",
		blockPattern:         "",
		running:              false,
		ctx:                  ctx}
}

func (mgr *Manager) Init() {
	defaultListen := "127.0.0.1:8877"
	// `-8080` means exclude 8080 port
	// also should move to configuration file
	defaultBlockPorts := []string{"6000-65536", "-8080", "-9261", "-10025", "-10027", "-10028", "-10029"}
	defaultBlockList := []string{
		"^127\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$",
		"^10\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$",
		"^172\\.1[6-9]{1}[0-9]{0,1}\\.[0-9]{1,3}\\.[0-9]{1,3}$",
		"^172\\.2[0-9]{1}[0-9]{0,1}\\.[0-9]{1,3}\\.[0-9]{1,3}$",
		"^172\\.3[0-1]{1}[0-9]{0,1}\\.[0-9]{1,3}\\.[0-9]{1,3}$",
		"^192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3}$",
		// TODO these should move to configuration file
		".*youku",
		".*tudou",
		".*iqiyi",
		".*ku6",
		".*qvod",
		".*letv",
	}

	for _, p := range defaultBlockPorts {
		mgr.AddToBlockPorts(p)
	}
	mgr.blockList = defaultBlockList
	mgr.UpdateBlockPattern()
	mgr.listen = defaultListen
}

func (mgr *Manager) AddToBlockList(addr string) {
	mgr.blockList = append(mgr.blockList, addr)
	mgr.UpdateBlockPattern()
}

func (mgr *Manager) UpdateBlockPattern() {
	mgr.Lock()
	defer mgr.Unlock()
	mgr.blockPattern = fmt.Sprintf("(%s)", strings.Join(mgr.blockList, "|"))
}

func (mgr *Manager) AddToBlockPorts(port string) {
	parts := strings.Split(port, "-")
	if len(parts) != 1 && len(parts) != 2 {
		return
	} else if parts[0] == "" {
		if exclude, err := strconv.Atoi(parts[1]); err != nil {
			return
		} else {
			mgr.Lock()
			mgr.excludeBlockPorts = append(mgr.excludeBlockPorts, exclude)
			mgr.Unlock()
		}
	} else {
		p0, err := strconv.Atoi(parts[0])
		if err != nil {
			return
		}
		p1, err := strconv.Atoi(parts[1])
		if err != nil {
			return
		}
		mgr.Lock()
		mgr.blockPortRanges = append(mgr.blockPortRanges, []int{p0, p1})
		mgr.Unlock()
	}
}

func (mgr *Manager) isBlockPort(port int) bool {
	mgr.Lock()
	defer mgr.Unlock()
	if port > MaxTCPPort {
		return true
	}
	for _, e := range mgr.excludeBlockPorts {
		if port == e {
			return false
		}
	}
	for _, r := range mgr.blockPortRanges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

func (mgr *Manager) IsBlock(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		logf("failed to split invalid address %v", err)
		return true
	}
	p, _ := strconv.Atoi(port)
	if mgr.isBlockPort(p) {
		return true
	}

	mgr.Lock()
	defer mgr.Unlock()
	matched, err := regexp.MatchString(mgr.blockPattern, host)
	if err != nil {
		return true
	}
	return matched
}

func (mgr *Manager) AddTCPRelay(key string, l net.Listener) {
	mgr.Lock()
	defer mgr.Unlock()
	mgr.relays[key] = append(mgr.relays[key], l)
}

func (mgr *Manager) AddUDPRelay(key string, c net.PacketConn) {
	mgr.Lock()
	defer mgr.Unlock()
	mgr.relays[key] = append(mgr.relays[key], c)
}

func (mgr *Manager) GetRelays(key string) ([]interface{}, bool) {
	mgr.Lock()
	defer mgr.Unlock()
	if val, ok := mgr.relays[key]; ok {
		return val, ok
	}
	return nil, false
}

func (mgr *Manager) RemoveRelay(key string) {
	mgr.Lock()
	defer mgr.Unlock()
	delete(mgr.relays, key)
}

func (mgr *Manager) AddDownloadLimitBucket(key string, rate float64, capacity int64) {
	mgr.Lock()
	defer mgr.Unlock()
	if rate == 0 {
		rate = 104857600 // 100MB/s
	}
	if capacity == 0 {
		capacity = 104857600
	}
	mgr.DownloadLimitBuckets[key] = ratelimit.NewBucketWithRate(rate, capacity)
}

func (mgr *Manager) AddUploadLimitBucket(key string, rate float64, capacity int64) {
	mgr.Lock()
	defer mgr.Unlock()
	if rate == 0 {
		rate = 104857600 // 100MB/s
	}
	if capacity == 0 {
		capacity = 104857600
	}
	mgr.UploadLimitBuckets[key] = ratelimit.NewBucketWithRate(rate, capacity)
}

func (mgr *Manager) GetDownloadLimitBucket(key string) *ratelimit.Bucket {
	for {
		mgr.Lock()
		val, ok := mgr.DownloadLimitBuckets[key]
		mgr.Unlock()
		if ok {
			return val.(*ratelimit.Bucket)
		}
		mgr.AddDownloadLimitBucket(key, 0, 0)
	}
}

func (mgr *Manager) GetUploadLimitBucket(key string) *ratelimit.Bucket {
	for {
		mgr.Lock()
		val, ok := mgr.UploadLimitBuckets[key]
		mgr.Unlock()
		if ok {
			return val.(*ratelimit.Bucket)
		}
		mgr.AddUploadLimitBucket(key, 0, 0)
	}
}

func (mgr *Manager) RemoveLimitBuckets(key string) {
	mgr.Lock()
	defer mgr.Unlock()
	delete(mgr.DownloadLimitBuckets, key)
	delete(mgr.UploadLimitBuckets, key)
}

func (mgr *Manager) UpdateStats(port string, dataLen int) {
	mgr.Lock()
	defer mgr.Unlock()
	mgr.stats[port] += dataLen
}

func (mgr *Manager) ClearStats() {
	mgr.Lock()
	defer mgr.Unlock()
	mgr.stats = make(map[string]int)
}

func (mgr *Manager) ManagementService() {
	serverAddr, err := net.ResolveUDPAddr("udp", mgr.listen)
	if err != nil {
		fmt.Errorf("error resolve addr: %v\n", err)
	}
	mgr.serverAddr = serverAddr
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		fmt.Errorf("error listen udp: %v\n", err)
	}
	defer serverConn.Close()
	mgr.serverConn = serverConn

	fmt.Printf("management service accept request on %s\n", mgr.listen)

	for {
		if !mgr.running {
			break
		} else {
			buf := make([]byte, 1506)
			n, addr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				fmt.Printf("fail read: %v\n", err)
			}
			mgr.clientAddr = addr
			go handleReq(buf[0:n], mgr)
		}
	}
}

func (mgr *Manager) Send(data []byte) error {
	if mgr.clientAddr != nil {
		_, err := mgr.serverConn.WriteToUDP(data, mgr.clientAddr)
		if err != nil {
			return err
		}
		return nil
	}
	return nil
}

func (mgr *Manager) StatsSender() {
	for {
		if !mgr.running {
			break
		} else {
			stats, err := json.Marshal(mgr.stats)
			if err != nil {
				fmt.Printf("fail marshal stats: %v\n", err)
			}
			statsStr := fmt.Sprintf("stat: %s", string(stats))
			if mgr.clientAddr != nil {
				if err = mgr.Send([]byte(statsStr)); err != nil {
					fmt.Printf("fail send statistics: %v\n", err)
				}
			}
			mgr.ClearStats()
			time.Sleep(10 * time.Second)
		}
	}
}

func (mgr *Manager) Run() {
	mgr.running = true
	go mgr.ManagementService()
	go mgr.StatsSender()
}

func (mgr *Manager) Stop() {
	mgr.running = false
}

func (mgr *Manager) Destroy() {
	mgr.Stop()
}

func parseCommand(data string) (string, string) {
	parts := strings.SplitN(data, ":", 2)
	if len(parts) < 2 {
		return data, ""
	}
	return parts[0], parts[1]
}

func (mgr *Manager) AddServer(configStr string) bool {
	config := &Config{}
	if err := json.Unmarshal([]byte(configStr), config); err != nil {
		fmt.Println("error", err)
	}
	port := strconv.Itoa(config.ServerPort)
	addr := ":" + port
	password := config.Password
	var key []byte

	if _, ok := mgr.GetRelays(port); ok {
		logf("server %s already runing", port)
		return false
	}

	ciph, err := core.PickCipher(config.Method, key, password)
	if err != nil {
		logf("error pick cipher for port %s: %v", port, err)
		return false
	}
	mgr.AddUploadLimitBucket(port, float64(config.UploadRateLimit), int64(config.UploadRateLimit))
	mgr.AddDownloadLimitBucket(port, float64(config.DownloadRateLimit), int64(config.DownloadRateLimit))
	go udpRemote(mgr.ctx, addr, ciph.PacketConn)
	go tcpRemote(mgr.ctx, addr, ciph.StreamConn)
	return true
}

func (mgr *Manager) RemoveServer(configStr string) bool {
	config := &Config{}
	if err := json.Unmarshal([]byte(configStr), config); err != nil {
		fmt.Println("error", err)
	}
	port := strconv.Itoa(config.ServerPort)

	relays, ok := mgr.GetRelays(port)
	if !ok {
		logf("server %s does not exist", port)
		return false
	}

	for _, res := range relays {
		switch t := res.(type) {
		case net.Listener:
			// TODO gracefully shutdown
			if err := res.(net.Listener).Close(); err != nil {
				fmt.Printf("fail close relay resource: %v\n", err)
			}
		case net.PacketConn:
			// TODO gracefully shutdown
			if err := res.(net.PacketConn).Close(); err != nil {
				fmt.Printf("fail close relay resource: %v\n", err)
			}
		default:
			fmt.Printf("unexpected type of resource: %T\n", t)
		}
	}
	mgr.RemoveRelay(port)
	mgr.RemoveLimitBuckets(port)
	logf("remove server %s", port)
	return true
}

func handleReq(buf []byte, mgr *Manager) {
	data := string(buf)
	command, configStr := parseCommand(data)
	var err error

	switch command {
	case "add":
		if mgr.AddServer(configStr) {
			err = mgr.Send([]byte("ok"))
		} else {
			err = mgr.Send([]byte("fail"))
		}
	case "remove":
		if mgr.RemoveServer(configStr) {
			err = mgr.Send([]byte("ok"))
		} else {
			err = mgr.Send([]byte("fail"))
		}
	case "ping":
		err = mgr.Send([]byte("pong"))
	default:
		fmt.Println("unknown command")
	}

	if err != nil {
		fmt.Errorf("error handle management request: %v", err)
	}
}
