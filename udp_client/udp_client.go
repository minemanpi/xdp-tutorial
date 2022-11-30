package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/tevino/abool/v2"
	"golang.org/x/time/rate"
)

type Stats struct {
	mu          sync.RWMutex
	reqSent     int
	reqReceived int
	Data        []DataEntry `json:"data"`
}

type DataEntry struct {
	Start    int64         `json:"start"`
	Duration time.Duration `json:"duration"`
}

type ConcurrentLimiter struct {
	*rate.Limiter
	mu sync.Mutex
}

func (clim *ConcurrentLimiter) Wait(ctx context.Context) error {
	clim.mu.Lock()
	defer clim.mu.Unlock()
	return clim.Limiter.Wait(ctx)
}

func main() {

	rateLimit := flag.Float64("rate", float64(rate.Inf), "Rate limit (per client). Defaults to no limit.")
	numRequests := flag.Int("num-requests", 10000000, "Number of UDP requests to send, per client.")
	numClients := flag.Int("num-clients", 1, "Number of client threads to start.")
	globalRateLimit := flag.Float64("global-rate", float64(rate.Inf), "Global rate limit (for all clients). Defaults to no limit.")
	printMeasurements := flag.Bool("print-measurements", false, "Print measurements for each request.")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Printf("USAGE: udp_client [--rate RATE_LIMIT] [--num-clients NUM_CLIENTS] [--num-requests NUM_REQUESTS] [SERVER:PORT]")
		os.Exit(1)
	}
	server := flag.Arg(0)

	msg := []byte("get 0123456789012345")
	expectedResp := []byte("header00VALUE 0123456789012345 0 32\n" +
		"01234567890123450123456789012345\n" +
		"END")

	// Print config
	log.Printf("Config:\nNumber of clients: %d\nRate per client: %v req/sec\nGlobalRate: %v req/sec\nNumber of requests per client: %d\n", *numClients, *rateLimit, *globalRateLimit, *numRequests)

	// Resolve address
	udpAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		log.Fatalf("Failed to resolve address: %v", err)
	}
	stats := &Stats{}
	var wg sync.WaitGroup
	globalLimiter := &ConcurrentLimiter{
		Limiter: rate.NewLimiter(rate.Limit(*globalRateLimit), int(*globalRateLimit)),
	}

	go calculateThroughput(msg, expectedResp, stats)
	for i := 0; i < *numClients; i++ {
		wg.Add(1)
		go func() {
			sendMessages(
				udpAddr,
				msg,
				expectedResp,
				*numRequests,
				rate.NewLimiter(rate.Limit(*rateLimit), int(*rateLimit)),
				globalLimiter,
				stats,
			)
			wg.Done()
		}()
	}
	wg.Wait()
	if *printMeasurements {
		log.Println("Printing measurements...")
		b, err := json.Marshal(stats.Data)
		if err != nil {
			log.Fatalf("Failed to marshal json: %v", err)
		}
		fmt.Println(string(b))
		log.Println("Finished printing measurements!")
	}
}

func sendMessages(addr *net.UDPAddr, data, expectedReply []byte, numRequests int,
	limiter *rate.Limiter, globalLimiter *ConcurrentLimiter, stats *Stats) {

	conn, err := net.DialUDP("udp", nil, addr)
	log.Printf("Local address: %v\n", conn.LocalAddr())
	done := abool.New()
	if err != nil {
		log.Fatalf("Failed to connect: %v\n", err)
	}

	startTimes := sync.Map{}

	// Receive goroutine
	go func() {

		var replyBuf = make([]byte, 3*len(expectedReply))
		for {
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := conn.Read(replyBuf)
			if err != nil {
				log.Printf("Error reading server response: %v\n", err)
				if done.IsSet() {
					break
				}
				continue
			} else if n != 73 {
				// fmt.Printf("Server reply is not of the expected length (got %d, wanted %d): '%s'\n", n, len(expectedReply), replyBuf[:n])
			}
			endTime := time.Now()
			// fmt.Printf("Got reply: %s\n", string(replyBuf[:n]))
			reqID := decodeReqID(replyBuf[:8])
			val, ok := startTimes.Load(reqID)
			if !ok {
				log.Fatalf("Failed to find start time for req id %d\n", reqID)
			}
			startTime := val.(time.Time)
			stats.mu.Lock()
			stats.reqReceived++
			stats.Data = append(
				stats.Data,
				DataEntry{Start: startTime.UnixNano(), Duration: endTime.Sub(startTime)},
			)
			stats.mu.Unlock()
			startTimes.Delete(reqID)
		}
	}()

	for i := 0; i < numRequests; i++ {
		if err := limiter.Wait(context.Background()); err != nil {
			log.Printf("Error using rate limiter: %v\n", err)
			continue
		}
		if err := globalLimiter.Wait(context.Background()); err != nil {
			log.Printf("Error using global rate limiter: %v\n", err)
			continue
		}
		reqID := getNextReqID()
		startTimes.Store(reqID, time.Now())
		header := encodeReqID(reqID)
		msg := []byte(fmt.Sprintf("%s%s", string(header[:]), string(data)))
		// fmt.Printf("Sending message: %s\n", msg)
		n, err := conn.Write(msg)
		if err != nil {
			log.Printf("Error sending UDP packet: %v\n", err)
		} else if n != len(msg) {
			log.Printf("Error: Did not send all message bytes!\n")
		}
		stats.mu.Lock()
		stats.reqSent++
		stats.mu.Unlock()
	}
	// Wait a bit for the receive goroutine to get any last messages
	time.Sleep(3 * time.Second)
	done.Set()
}

func calculateThroughput(msg, expectedReply []byte, stats *Stats) {
	period := 5 * time.Second
	for {
		stats.mu.RLock()
		sentBefore := float64(stats.reqSent)
		receivedBefore := float64(stats.reqReceived)
		stats.mu.RUnlock()
		time.Sleep(period)
		stats.mu.RLock()
		sentAfter := float64(stats.reqSent)
		receivedAfter := float64(stats.reqReceived)
		stats.mu.RUnlock()

		sent := sentAfter - sentBefore
		received := receivedAfter - receivedBefore

		throughput := received / period.Seconds()
		mega := 1024 * 1024
		throughputMbps := throughput * float64(len(expectedReply)+len(msg)) * 8 / float64(mega)
		sendThroughput := sent / period.Seconds()

		log.Printf("Throughput: %.2f req/sec\n", throughput)
		log.Printf("Throughput: %.2f Mbps\n", throughputMbps)
		log.Printf("Send throughput: %.2f req/sec\n", sendThroughput)
	}
}

var (
	reqID    int32 = 0
	maxReqID int32 = 99999999
	reqIDMu  sync.Mutex
)

// getNextReqID generates the next request ID to use
func getNextReqID() int32 {
	reqIDMu.Lock()
	defer reqIDMu.Unlock()
	reqID++
	if reqID >= maxReqID {
		log.Fatal("Out of request IDs!")
	}
	return reqID
}

func encodeReqID(reqID int32) [8]byte {
	res := [8]byte{}
	for idx := range res {
		res[idx] = '0'
	}
	temp := strconv.Itoa(int(reqID))
	copy(res[len(res)-len(temp):], []byte(temp))
	return res
}

func decodeReqID(b []byte) int32 {
	res, err := strconv.Atoi(string(b))
	if err != nil {
		log.Fatalf("Failed to decode request id for array %v: %v", b, err)
	}
	return int32(res)
}

