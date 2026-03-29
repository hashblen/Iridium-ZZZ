package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/xtaci/kcp-go"
)

type Packet struct {
	Time       int64       `json:"time"`
	FromServer bool        `json:"fromServer"`
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
}

var playerGetTokenCsReqId uint16
var playerGetTokenScRspId uint16

var serverSeed uint64
var sentMs uint64

var initialKey []byte
var sessionKey []byte

var privateKey *rsa.PrivateKey

var captureHandler *pcap.Handle
var kcpMap map[string]*kcp.KCP
var packetFilter = make(map[string]bool)
var pcapFile *os.File

func openPcap(fileName string) {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenOffline(fileName)
	if err != nil {
		log.Println("Could not open pacp file", err)
		return
	}
	startSniffer()
}

func openCapture() {
	readKeys()
	var err error
	captureHandler, err = pcap.OpenLive(config.DeviceName, 1500, true, -1)
	if err != nil {
		log.Println("Could not open capture", err)
		return
	}

	if config.AutoSavePcapFiles {
		pcapFile, err = os.Create(time.Now().Format("06-01-02 15.04.05") + ".pcapng")
		if err != nil {
			log.Println("Could not create pcapng file", err)
		}
		defer pcapFile.Close()
	}

	startSniffer()
}

func closeHandle() {
	if captureHandler != nil {
		captureHandler.Close()
		captureHandler = nil
	}
	if pcapFile != nil {
		pcapFile.Close()
		pcapFile = nil
	}
}

func readKeys() {
	file, err := os.ReadFile("./data/Key.txt")
	if err != nil {
		log.Fatal("Could not load initial key @ ./data/Key.txt #1", err)
	}
	initialKeyString := strings.TrimSpace(string(file))

	decode, _ := base64.RawStdEncoding.DecodeString(initialKeyString)
	initialKey = decode

	playerGetTokenCsReqId = packetNameMap["PlayerGetTokenCsReq"]
	playerGetTokenScRspId = packetNameMap["PlayerGetTokenScRsp"]

	privateKeyFile, err := os.ReadFile("data/private_3.pem")
	if err != nil {
		log.Fatal("Could not read private key @ ./data/private_3.pem #3", err)
	}
	var priv *rsa.PrivateKey
	for {
		block, rest := pem.Decode(privateKeyFile)
		if block.Type == "RSA PRIVATE KEY" {
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				log.Println(err)
			}
			priv = k
			break
		}
		if len(rest) == 0 {
			log.Println(fmt.Errorf("failed to parse private key"))
			break
		}
	}
	privateKey = priv

	/*publicKeyFile, err := os.ReadFile("data/public_3.pem")
	if err != nil {
		log.Fatal("Could not read public key @ ./data/private_3.pem #3", err)
	}
	var pub *rsa.PublicKey
	for {
		block, rest := pem.Decode(publicKeyFile)
		if block.Type == "PUBLIC KEY" {
			k, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				log.Println(err)
			}
			pub = k
			break
		}
		if len(rest) == 0 {
			log.Println(fmt.Errorf("failed to parse private key"))
			break
		}
	}
	publicKey = pub*/
}

func startSniffer() {
	defer captureHandler.Close()

	err := captureHandler.SetBPFFilter("udp portrange 20501-20502")
	if err != nil {
		log.Println("Could not set the filter of capture")
		return
	}

	packetSource := gopacket.NewPacketSource(captureHandler, captureHandler.LinkType())
	packetSource.NoCopy = true

	kcpMap = make(map[string]*kcp.KCP)

	var pcapWriter *pcapgo.NgWriter
	if pcapFile != nil {
		pcapWriter, err = pcapgo.NewNgWriter(pcapFile, captureHandler.LinkType())
		if err != nil {
			log.Println("Could not create pcapng writer", err)
		}
	}

	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Println("Could not write packet to pcap file", err)
			}
		}

		capTime := packet.Metadata().Timestamp
		data := packet.ApplicationLayer().Payload()
		udp := packet.TransportLayer().(*layers.UDP)
		fromServer := udp.SrcPort == 20501 || udp.SrcPort == 20502

		if len(data) <= 20 {
			handleSpecialPacket(data, fromServer, capTime)
			continue
		}

		handleKcp(data, fromServer, capTime)
	}
}

func handleKcp(data []byte, fromServer bool, capTime time.Time) {
	//log.Println("Data in KCP:", base64.RawStdEncoding.EncodeToString(data))
	data = reformData(data)
	//log.Println("Data after reformat:", base64.RawStdEncoding.EncodeToString(data))
	conv := binary.LittleEndian.Uint32(data[:4])
	key := strconv.Itoa(int(conv))
	if fromServer {
		key += "svr"
	} else {
		key += "cli"
	}

	if _, ok := kcpMap[key]; !ok {
		kcpInstance := kcp.NewKCP(conv, func(buf []byte, size int) {})
		kcpInstance.WndSize(1024, 1024)
		kcpMap[key] = kcpInstance
	}
	kcpInstance := kcpMap[key]
	_ = kcpInstance.Input(data, true, true)

	size := kcpInstance.PeekSize()
	for size > 0 {
		kcpBytes := make([]byte, size)
		kcpInstance.Recv(kcpBytes)
		handleProtoPacket(kcpBytes, fromServer, capTime)
		size = kcpInstance.PeekSize()
	}
	kcpInstance.Update()
}

func handleSpecialPacket(data []byte, fromServer bool, timestamp time.Time) {
	sessionKey = nil
	switch binary.BigEndian.Uint32(data[:4]) {
	case 0xFF:
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke pls.")
		break
	case 404:
		buildPacketToSend(data, fromServer, timestamp, 0, "Disconnected.")
		break
	default:
		buildPacketToSend(data, fromServer, timestamp, 0, "Hamdshanke estamblished.")
		break
	}
}

func handleProtoPacket(data []byte, fromServer bool, timestamp time.Time) {
	key := binary.BigEndian.Uint32(data[:4])
	if key != 0x01234567 {
		log.Fatal("Head magic is wrong")
	}
	//log.Println("Data before xor:", base64.RawStdEncoding.EncodeToString(data))
	var xorPad []byte

	if sessionKey != nil {
		xorPad = sessionKey
	} else {
		xorPad = initialKey
	}

	packetId := binary.BigEndian.Uint16(data[4:6])
	var objectJson interface{}

	if packetId == playerGetTokenScRspId {
		header, body := getHeaderAndBody(data)
		data = body
		log.Println("Header:", base64.StdEncoding.EncodeToString(header))
		xorDecrypt(data, xorPad)
		//log.Println("Data after xor:", base64.RawStdEncoding.EncodeToString(data))
		data, objectJson = PlayerGetTokenScRspPacket(data, packetId, objectJson)
	} else if packetId == playerGetTokenCsReqId {
		header, body := getHeaderAndBody(data)
		data = body
		log.Println("Header:", base64.StdEncoding.EncodeToString(header))
		xorDecrypt(data, xorPad)
		data, objectJson = PlayerGetTokenCsReqPacket(data, packetId, timestamp, objectJson)
	} else {
		header, body := getHeaderAndBody(data)
		data = body
		log.Println("Header:", base64.StdEncoding.EncodeToString(header))
		clone := make([]byte, len(data))
		copy(clone, data)
		xorDecrypt(clone, xorPad)
		_, err := parseProto(packetId, clone)
		if errors.Is(err, ErrProtoNotFound) {
			log.Println("Unknown proto packet", packetId)
			return
		} else if err != nil {
			log.Println("Cracking seed...", sentMs)
			seed := sentMs
			seed, xorPad = bruteforce(seed, serverSeed, data, packetId)
			if seed == 0 || xorPad == nil {
				log.Println("Could not bruteforce, skipping...")
			} else {
				sessionKey = xorPad
			}
		}
		xorDecrypt(data, xorPad)
		//log.Println("Data after xor:", base64.RawStdEncoding.EncodeToString(data))
		objectJson = parseProtoToInterface(packetId, data)
	}

	buildPacketToSend(data, fromServer, timestamp, packetId, objectJson)
}

func PlayerGetTokenCsReqPacket(data []byte, packetId uint16, timestamp time.Time, objectJson interface{}) ([]byte, interface{}) {
	dMsg, err := parseProto(packetId, data)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenCsReq proto", err)
		closeHandle()
	}
	oj, err := dMsg.MarshalJSON()
	if err != nil {
		log.Println("Could not parse PlayerGetTokenCsReq proto", err)
		closeHandle()
	}
	err = json.Unmarshal(oj, &objectJson)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenCsReq proto", err)
		closeHandle()
	}
	sentMs = uint64(timestamp.UnixMilli())
	return data, objectJson
}

func PlayerGetTokenScRspPacket(data []byte, packetId uint16, objectJson interface{}) ([]byte, interface{}) {
	dMsg, err := parseProto(packetId, data)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	oj, err := dMsg.MarshalJSON()
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	err = json.Unmarshal(oj, &objectJson)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	seedStr := dMsg.GetFieldByName("server_rand_key").(string)
	seed, err := base64.StdEncoding.DecodeString(seedStr)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	decrBytes, err := decrypt(privateKey, seed)
	if err != nil {
		log.Println("Could not parse PlayerGetTokenScRsp proto", err)
		closeHandle()
	}
	decrSeed := binary.LittleEndian.Uint64(decrBytes)
	serverSeed = decrSeed
	log.Println("server seed:", serverSeed)

	return data, objectJson
}

func buildPacketToSend(data []byte, fromSever bool, timestamp time.Time, packetId uint16, objectJson interface{}) {
	packet := &Packet{
		Time:       timestamp.UnixMilli(),
		FromServer: fromSever,
		PacketId:   packetId,
		PacketName: GetProtoNameById(packetId),
		Object:     objectJson,
		Raw:        data,
	}

	jsonResult, err := json.Marshal(packet)
	if err != nil {
		log.Println("Json marshal error", err)
	}
	logPacket(packet)

	if GetProtoNameById(packetId) != "" && packetFilter[GetProtoNameById(packetId)] {
		return
	}
	sendStreamMsg(string(jsonResult))
}

func logPacket(packet *Packet) {
	from := "[Client]"
	if packet.FromServer {
		from = "[Server]"
	}
	forward := ""
	if strings.Contains(packet.PacketName, "Rsp") {
		forward = "<--"
	} else if strings.Contains(packet.PacketName, "Req") {
		forward = "-->"
	} else if strings.Contains(packet.PacketName, "Notify") && packet.FromServer {
		forward = "<-i"
	} else if strings.Contains(packet.PacketName, "Notify") {
		forward = "i->"
	}

	log.Println(color.GreenString(from),
		"\t",
		color.CyanString(forward),
		"\t",
		color.RedString(packet.PacketName),
		color.YellowString("#"+strconv.Itoa(int(packet.PacketId))),
		"\t",
		len(packet.Raw),
	)
}
