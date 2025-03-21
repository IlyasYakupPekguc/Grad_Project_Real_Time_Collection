package main

// Adding the required Kafka libraries alongside existing imports
import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/IBM/sarama" // Kafka client library
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Keeping your existing data structures - they work well for our needs
type PacketData struct {
	Interface       string    `json:"interface"`
	Timestamp       time.Time `json:"timestamp"`
	Size            int       `json:"size"`
	Protocol        string    `json:"protocol"`
	SourceIP        string    `json:"source_ip"`
	DestinationIP   string    `json:"destination_ip"`
	SourcePort      int       `json:"source_port,omitempty"`
	DestinationPort int       `json:"destination_port,omitempty"`
	TTL             int       `json:"ttl,omitempty"`
	TCPFlags        string    `json:"tcp_flags,omitempty"`
	PacketType      string    `json:"packet_type"`
	Direction       string    `json:"direction"`
	PayloadHash     string    `json:"payload_hash,omitempty"`
	Hour            int       `json:"hour"`
	Minute          int       `json:"minute"`
	Second          int       `json:"second"`
	DayOfWeek       string    `json:"day_of_week"`
}

// We'll keep this for stats tracking, but won't use it for actual storage
type NetworkData struct {
	StartTime   time.Time    `json:"start_time"`
	EndTime     time.Time    `json:"end_time"`
	PacketCount int          `json:"packet_count"`
	Packets     []PacketData `json:"packets"` // We won't use this for Kafka streaming
}

// Function to create a Kafka producer
func createKafkaProducer(brokerList []string) (sarama.SyncProducer, error) {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll // Wait for all replicas to acknowledge
	config.Producer.Retry.Max = 5                    // Retry up to 5 times
	config.Producer.Return.Successes = true          // We need this to be true to get confirmations

	// Create the producer
	producer, err := sarama.NewSyncProducer(brokerList, config)
	if err != nil {
		return nil, err
	}

	return producer, nil
}

// Modified capturePackets function to send directly to Kafka
func capturePackets(deviceName string, wg *sync.WaitGroup, producer sarama.SyncProducer, kafkaTopic string, stats *NetworkData) {
	defer wg.Done()

	handle, err := pcap.OpenLive(
		deviceName,
		1600,
		true,
		30*time.Second,
	)
	if err != nil {
		log.Printf("Error opening device %s: %v", deviceName, err)
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter("tcp or udp")
	if err != nil {
		log.Printf("Error setting BPF filter on %s: %v", deviceName, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Printf("Started capturing on interface: %s\n", deviceName)

	for packet := range packetSource.Packets() {
		timestamp := packet.Metadata().Timestamp

		packetData := PacketData{
			Interface: deviceName,
			Timestamp: timestamp,
			Size:      len(packet.Data()),
			Hour:      timestamp.Hour(),
			Minute:    timestamp.Minute(),
			Second:    timestamp.Second(),
			DayOfWeek: timestamp.Weekday().String(),
		}

		if netLayer := packet.NetworkLayer(); netLayer != nil {
			packetData.PacketType = netLayer.LayerType().String()

			// Still process only IPv4 packets
			if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
				ipv4, _ := ipv4Layer.(*layers.IPv4)
				packetData.SourceIP = ipv4.SrcIP.String()
				packetData.DestinationIP = ipv4.DstIP.String()

				if transportLayer := packet.TransportLayer(); transportLayer != nil {
					packetData.Protocol = transportLayer.LayerType().String()
					if tcp, ok := transportLayer.(*layers.TCP); ok {
						packetData.SourcePort = int(tcp.SrcPort)
						packetData.DestinationPort = int(tcp.DstPort)
						packetData.TTL = int(tcp.Window)
						packetData.TCPFlags = fmt.Sprintf("SYN=%v ACK=%v FIN=%v", tcp.SYN, tcp.ACK, tcp.FIN)
					}
					if udp, ok := transportLayer.(*layers.UDP); ok {
						packetData.SourcePort = int(udp.SrcPort)
						packetData.DestinationPort = int(udp.DstPort)
					}

					// Convert packet to JSON for Kafka
					packetJSON, err := json.Marshal(packetData)
					if err != nil {
						log.Printf("Error marshaling packet data: %v", err)
						continue
					}

					// Send to Kafka
					msg := &sarama.ProducerMessage{
						Topic: kafkaTopic,
						Value: sarama.StringEncoder(packetJSON),
					}

					_, _, err = producer.SendMessage(msg)
					if err != nil {
						log.Printf("Error sending message to Kafka: %v", err)
					} else {
						// Update stats (for monitoring purposes)
						stats.PacketCount++
						if stats.PacketCount%1000 == 0 {
							fmt.Printf("\rPackets sent to Kafka: %d", stats.PacketCount)
						}
					}

					// Debug output (keeping your existing format)
					fmt.Printf("\nPacket on %s:\n", deviceName)
					fmt.Printf("Time: %v\n", timestamp.Format("15:04:05"))
					fmt.Printf("Size: %d bytes\n", len(packet.Data()))
					fmt.Printf("Protocol: %s\n", packetData.Protocol)
					fmt.Printf("Source: %s:%d\n", packetData.SourceIP, packetData.SourcePort)
					fmt.Printf("Destination: %s:%d\n", packetData.DestinationIP, packetData.DestinationPort)
				}
			}
		}
	}
}

func main() {
	// Kafka configuration
	brokers := []string{"localhost:9092"} // Default Kafka broker address, modify as needed
	topic := "network-packets"            // Kafka topic to send packets to

	// Create Kafka producer
	producer, err := createKafkaProducer(brokers)
	if err != nil {
		log.Fatal("Failed to create Kafka producer:", err)
	}
	defer func() {
		if err := producer.Close(); err != nil {
			log.Println("Failed to close Kafka producer:", err)
		}
	}()

	// Find available devices (keeping your existing code)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error finding devices:", err)
	}

	if len(devices) == 0 {
		log.Fatal("No network interfaces found")
	}

	fmt.Println("Available interfaces:")
	for i, device := range devices {
		fmt.Printf("%d. %s\n", i+1, device.Name)
		fmt.Printf("   Description: %s\n", device.Description)
		for _, address := range device.Addresses {
			fmt.Printf("   IP: %s\n", address.IP)
		}
		fmt.Println("----------------------------------------")
	}

	var wg sync.WaitGroup

	// Create network stats for monitoring
	stats := &NetworkData{
		StartTime: time.Now(),
	}

	// Start packet capture on all interfaces
	for _, device := range devices {
		wg.Add(1)
		go capturePackets(device.Name, &wg, producer, topic, stats)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("\nStarted capturing packets and sending to Kafka. Press Ctrl+C to stop...")

	// Wait for termination signal
	<-sigChan

	fmt.Println("\nStopping capture...")
	stats.EndTime = time.Now()
	duration := stats.EndTime.Sub(stats.StartTime)

	fmt.Printf("\nCapture summary:\n")
	fmt.Printf("Total packets captured and sent to Kafka: %d\n", stats.PacketCount)
	fmt.Printf("Total runtime: %v\n", duration)
	fmt.Printf("Average rate: %.2f packets/sec\n", float64(stats.PacketCount)/duration.Seconds())

	wg.Wait()
}
