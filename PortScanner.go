package portscanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/elchemista/port-scanner/predictors"
	"github.com/elchemista/port-scanner/predictors/webserver"
)

const UNKNOWN = "<unknown>"

type PortScanner struct {
	host         string
	predictors   []predictors.Predictor
	timeout      time.Duration
	threads      int
	usePredictor bool
}

func NewPortScanner(host string, timeout time.Duration, threads int) *PortScanner {
	return &PortScanner{
		host:         host,
		predictors:   []predictors.Predictor{&webserver.ApachePredictor{}, &webserver.NginxPredictor{}},
		timeout:      timeout,
		threads:      threads,
		usePredictor: true,
	}
}

func (ps *PortScanner) TogglePredictor(usePredictor bool) {
	ps.usePredictor = usePredictor
}

func (ps *PortScanner) SetThreads(threads int) {
	ps.threads = threads
}

func (ps *PortScanner) SetTimeout(timeout time.Duration) {
	ps.timeout = timeout
}

func (ps *PortScanner) RegisterPredictor(predictor predictors.Predictor) {
	for _, p := range ps.predictors {
		if p == predictor {
			return
		}
	}
	ps.predictors = append(ps.predictors, predictor)
}

func (ps PortScanner) IsOpen(port int) bool {
	address := ps.hostPort(port)
	conn, err := net.DialTimeout("tcp", address, ps.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (ps PortScanner) GetOpenedPorts(start, end int) []int {
	var openPorts []int
	var mu sync.Mutex
	wg := sync.WaitGroup{}
	sem := make(chan struct{}, ps.threads)

	for port := start; port <= end; port++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			if ps.IsOpen(port) {
				mu.Lock()
				openPorts = append(openPorts, port)
				mu.Unlock()
			}
			<-sem
		}(port)
	}

	wg.Wait()
	return openPorts
}

func (ps PortScanner) hostPort(port int) string {
	return fmt.Sprintf("%s:%d", ps.host, port)
}

func (ps PortScanner) DescribePort(port int) string {
	if !ps.usePredictor {
		return ps.predictPort(port)
	}

	description := UNKNOWN
	if ps.IsHttp(port) {
		description = ps.PredictUsingPredictor(ps.hostPort(port))
	} else {
		assumed := ps.predictPort(port)
		description = assumed
		if assumed == UNKNOWN {
			description = ps.PredictUsingPredictor(ps.hostPort(port))
		}
		if assumed == "MySQL" {
			description = ps.getMySQLVersion(port, assumed)
		}
	}

	return description
}

func (ps PortScanner) IsHttp(port int) bool {
	return port == 80 || port == 8080
}

func (ps PortScanner) PredictUsingPredictor(host string) string {
	for _, predictor := range ps.predictors {
		conn, err := ps.openConn(host)
		if err != nil {
			continue
		}
		defer conn.Close()
		if result := predictor.Predict(host); len(result) > 0 {
			return result
		}
	}
	return UNKNOWN
}

func (ps PortScanner) openConn(host string) (net.Conn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", host)
	if err != nil {
		return nil, err
	}
	return net.DialTimeout("tcp", tcpAddr.String(), ps.timeout)
}

func (ps PortScanner) getMySQLVersion(port int, assumed string) string {
	conn, err := ps.openConn(ps.hostPort(port))
	if err != nil {
		return assumed
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	result := make([]byte, 20)
	if _, err := conn.Read(result); err == nil {
		return assumed + " version: " + string(result)
	}
	return assumed
}

var KNOWN_PORTS = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	66:    "Oracle SQL*NET?",
	69:    "TFTP",
	80:    "HTTP",
	88:    "Kerberos",
	109:   "POP2",
	110:   "POP3",
	118:   "SQL Service?",
	123:   "NTP",
	137:   "NetBIOS",
	139:   "NetBIOS",
	143:   "IMAP",
	150:   "SQL-Net?",
	194:   "IRC",
	443:   "HTTPS",
	445:   "Samba",
	465:   "SMTP over SSL",
	554:   "RTSP",
	5800:  "VNC Remote Desktop",
	631:   "CUPS",
	993:   "IMAP over SSL",
	995:   "POP3 over SSL",
	1433:  "Microsoft SQL Server",
	1434:  "Microsoft SQL Monitor",
	3306:  "MySQL",
	3389:  "Remote Desktop Protocol (RDP)",
	3396:  "Novell NDPS Printer Agent",
	3535:  "SMTP (Alternate)",
	5432:  "PostgreSQL",
	6379:  "Redis",
	8080:  "HTTP Alternate",
	9160:  "Cassandra",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
	28017: "MongoDB Web Admin",
}

func (ps PortScanner) predictPort(port int) string {
	if desc, exists := KNOWN_PORTS[port]; exists {
		return desc
	}
	return UNKNOWN
}
