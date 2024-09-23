package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/cosmos/go-bip39"
	"github.com/dcnetio/gothreads-lib/core/thread"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
	mbase "github.com/multiformats/go-multibase"
)

var teerandom []byte

const (
	version          = "0.1.8"
	commitBasePubkey = "bl3kr5jjklu2iijnmyhz7cy5lz3h5xhrlp7sim54bjhc4v3ztzfdq" //技术委员会用于发布dcnode升级版本的pubkey
	dcport           = 6667                                                    //dc节点监听的升级用固定端口 6667
	listenPort       = 6666                                                    //升级辅助程序监听的固定端口6666，供新版本dc节点程序调用
	DialTimeout      = 10 * time.Second
	authPath         = "/opt/dcnetio/data/init/auth"
)

var EnclaveId string
var commitPubkey thread.PubKey
var enclaveIdSignature string //技术委员会对当前升级辅助程序的enclaveid的签名授权,需要从配置文件获取
var log = logging.Logger("dcupgrade")
var SecretExistFlag = false
var DcnodeGetSecretSuccessFlag = false //新版本程序获取节点密钥成功标志

func main() {
	//获取当前的enclaveID：
	InitEnclaveId()
	fmt.Printf("DcUpgrade Version: %s ,encalveId: %s \r\n", version, EnclaveId)
	fmt.Printf("listen on port: %d \r\n", listenPort)
	fmt.Printf("interact with dcnode on port: %d \r\n", dcport)
	//生成初始随机数
	randNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	randNumber, err := rand.Int(rand.Reader, randNumberLimit)
	if err != nil {
		log.Error(err)
		return
	}
	teerandom = randNumber.Bytes()
	//生成技术委员会的pubkey
	_, commitPubkeyBytes, err := mbase.Decode(commitBasePubkey)
	if err != nil {
		log.Error(err)
		return
	}
	cpubkey, err := crypto.UnmarshalEd25519PublicKey(commitPubkeyBytes)
	if err != nil {
		fmt.Printf("client request secret fail, err: %v\r\n", err)
		return
	}
	commitPubkey = thread.NewLibp2pPubKey(cpubkey)
	//从配置文件中获取技术委员会对当前enclaveid 的签名
	initFlag := initAuthSignatureFromConfigfile()
	if !initFlag {
		return
	}
	//启动节点加密数据密码查询服务（只有指定的enclave可以获取）
	http.HandleFunc("/teerandom", func(w http.ResponseWriter, r *http.Request) { //申请随机数
		randNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		randNumber, err := rand.Int(rand.Reader, randNumberLimit)
		if err != nil {
			fmt.Printf("softupdate: generate randnumber fail\r\n")
			w.Write([]byte{})
		}
		teerandom = randNumber.Bytes()
		values := r.URL.Query()["verifyreport"] //反馈数据用这个verifyreport对应的enclave进行验证
		if len(values) == 0 {
			http.Error(w, "invalid parameter", http.StatusBadRequest)
			return
		}
		encodedVerifyReport := values[0]
		_, verifyReport, err := mbase.Decode(encodedVerifyReport)
		if err != nil {
			http.Error(w, "invalid parameter", http.StatusBadRequest)
			return
		}
		teerandomHash := sha512.Sum512(teerandom)
		localReport, err := enclave.GetLocalReport(teerandomHash[:], verifyReport)
		if err != nil {
			fmt.Printf("softupdate:  get tee local report fail\n")
			w.Write([]byte{})
		}
		w.Write(localReport) //将随机数hash值包含进本地认证包中，并返回
		fmt.Println("softupdate:  teerandom response success")
	})
	http.HandleFunc("/exit", handleExit)
	http.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf("%s@%s", EnclaveId, version)))
	})
	http.HandleFunc("/secretflag", func(w http.ResponseWriter, r *http.Request) {
		if SecretExistFlag {
			w.Write([]byte("true"))
		} else {
			w.Write([]byte("false"))
		}
	})
	http.HandleFunc("/upgradeflag", func(w http.ResponseWriter, r *http.Request) {
		if DcnodeGetSecretSuccessFlag {
			w.Write([]byte("true"))
		} else {
			w.Write([]byte("false"))
		}
	})
	http.HandleFunc("/secret", secretQuery)           //申请节点加密密码，调用本接口前需要先调用申请随机数方法/teerandom
	target := fmt.Sprintf("127.0.0.1:%d", listenPort) //只允许本地查询
	go func() {
		err = http.ListenAndServe(target, nil)
		if err != nil {
			fmt.Printf("http.ListenAndServe err: %v\n", err)
		} else {
			fmt.Printf("start http listen on target:   %s\n", target)
		}

	}()
	//定期扫描本地.secret文件是否存在
	go taskForNodeSecret()
	handleInterrupt()
}

func handleInterrupt() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	fmt.Println("Gracefully stopping... (press Ctrl+C again to force)")
	os.Exit(1)
}

type SecretQueryResult struct {
	EnclaveSignature []byte //技术委员会对当前程序enclaveid的签名（确保上游的enclave是有效的，防止恶意输入假密码给升级程序或升级后的节点程序）
	EncryptSecret    []byte //用申请节点密码请求方发过来的公钥加密后的节点密码
	Pubkey           []byte //随机生成的校验LocalReport中reportData中的签名的公钥
	LocalReport      []byte //包含当前程序生成的随机私钥对encryptSecret的签名的localteereport（确保加密后的节点密码没有在通信过程中被串改）
}

// 加密数据密码查询服务，参数：pubkey，authSignature，teereport
func secretQuery(w http.ResponseWriter, r *http.Request) {
	fmt.Println("softupdate:  receive secret request")
	//提取出请求的数据包，包含local teereport，
	values := r.URL.Query()["pubkey"] //反馈数据用这个pubkey加密
	if len(values) == 0 {
		http.Error(w, "secretQuery: invalid parameter", http.StatusBadRequest)
		return
	}
	reqBasePubkey := values[0]
	values = r.URL.Query()["authSignature"] //授权签名
	if len(values) == 0 {
		http.Error(w, "secretQuery: invalid parameter", http.StatusBadRequest)
		return
	}
	encodeAuthSignature := values[0]
	values = r.URL.Query()["teereport"] //包含调用本请求前申请的随机数的teereport
	if len(values) == 0 {
		http.Error(w, "secretQuery: invalid parameter", http.StatusBadRequest)
		return
	}
	encodedReport := values[0]
	_, teeReport, err := mbase.Decode(encodedReport)
	if err != nil {
		http.Error(w, fmt.Sprintf("client request secret fail,mbase.Decode err: %v\r\n", err), http.StatusBadRequest)
		return
	}
	//解析并验证本地 teeReport,report里面包含密码交换使用的临时pubkey，包含程序自身的enclaveid，及升级私钥对enclaveid的签名等数据
	report, err := enclave.VerifyLocalReport(teeReport)
	if err != nil {
		http.Error(w, fmt.Sprintf("client request secret fail,VerifyLocalReport err: %v\r\n", err), http.StatusBadRequest)
		return
	}
	//校验发起请求的enclaveid是否是技术委员会授权的
	_, authSignature, err := mbase.Decode(encodeAuthSignature)
	if err != nil {
		http.Error(w, fmt.Sprintf("client request secret fail,mbase.Decode err: %v\r\n", err), http.StatusBadRequest)
		return
	}
	enclaveId := hex.EncodeToString(report.UniqueID) //获取不带0x开头的enclaveid的16进制字符串
	ok, err := commitPubkey.Verify([]byte(enclaveId), authSignature)
	if err != nil || !ok {
		http.Error(w, fmt.Sprintf("secretQuery- invalid requset enclaveid:%s,signature:%s, err: %v\r\n", enclaveId, encodeAuthSignature, err), http.StatusBadRequest)
		return
	}
	_, reqPubkey, err := mbase.Decode(reqBasePubkey)
	if err != nil {
		http.Error(w, fmt.Sprintf("client request secret fail,reqBasePubkey err: %v\r\n", err), http.StatusBadRequest)
		return
	}
	cpubkey, err := crypto.UnmarshalEd25519PublicKey([]byte(reqPubkey))
	if err != nil {
		http.Error(w, fmt.Sprintf("client request secret fail,UnmarshalEd25519PublicKey err: %v\r\n", err), http.StatusBadRequest)
		return
	}
	pubkey := thread.NewLibp2pPubKey(cpubkey)
	signature := report.Data
	teerandomHash := sha512.Sum512(teerandom)
	ok, err = pubkey.Verify(teerandomHash[:], signature)
	if err != nil || !ok { //签名校验没通过，传输过程中pubkey可能被修改导致
		w.Write([]byte{})
		fmt.Printf("client request secret fail,signature verify err: %v\r\n", err)
		return
	}
	//从文件中读出节点密码
	if _, err := os.Stat(".secret"); os.IsNotExist(err) { //本地不存在节点加密密码，返回空
		w.Write([]byte{})
		fmt.Printf("client request secret fail, err: %v\r\n", err)
		return
	}
	sealedSecretBytes, err := os.ReadFile(".secret")
	if err != nil {
		w.Write([]byte{})
		fmt.Printf("client request secret fail, err: %v\r\n", err)
		return
	}
	//enclave.SealWithUniqueKey()
	secretBytes, err := ecrypto.Unseal(sealedSecretBytes, nil)
	if err != nil { //解封失败，.secret与当前的升级程序不兼容，删除文件重新生成
		os.Remove(".secret")
		w.Write([]byte{})
		fmt.Printf("client request secret fail, unseal err: %v\r\n", err)
		return
	}
	encryptSecret, err := pubkey.Encrypt([]byte(secretBytes))
	if err != nil {
		w.Write([]byte{})
		fmt.Printf("client request secret fail, encrypt err: %v\r\n", err)
		return
	}
	privKey, err := getRandomPrivKey()
	if err != nil {
		fmt.Printf("get  random privkey fail,  err: %v\r\n", err)
		w.Write([]byte{})
		return
	}
	pub, _ := privKey.GetPublic().Raw()
	//对加密的节点密码进行签名
	signature, err = privKey.Sign(encryptSecret)
	if err != nil {
		fmt.Printf("  sign encryptSecret fail,  err: %v\r\n", err)
		w.Write([]byte{})
		return
	}
	//生成本地teereport
	localReport, err := enclave.GetLocalReport(signature, teeReport)
	if err != nil {
		fmt.Printf("GetLocalReport fail,  err: %v\r\n", err)
		w.Write([]byte{})
		return
	}
	_, enclaveIdSignatureBytes, err := mbase.Decode(enclaveIdSignature)
	if err != nil {
		w.Write([]byte{})
		return
	}
	queryResult := SecretQueryResult{
		EnclaveSignature: enclaveIdSignatureBytes,
		EncryptSecret:    encryptSecret,
		Pubkey:           pub,
		LocalReport:      localReport,
	}
	queryResultBytes, err := json.Marshal(queryResult)
	if err != nil {
		w.Write([]byte{})
		fmt.Printf("queryResult marshal  err: %v\r\n", err)
		return
	}
	w.Write(queryResultBytes)
	fmt.Println("softupdate:  secret response success")
	DcnodeGetSecretSuccessFlag = true
}

// 接收到程序退出指令（只接收本机发送的指令）
func handleExit(w http.ResponseWriter, r *http.Request) {
	fmt.Println("receive  exit command，dcupgrade exit.......")
	w.Write([]byte{})
	os.Exit(1)
}

// 获取dcnode的节点密码进行加密保存，如果本地已经存在节点密码，则不再生成
func taskForNodeSecret() {
	showFlag := false
	tricker := time.NewTicker(time.Second * 10)
	fmt.Println("task for getting node secret start")
	for range tricker.C {
		if _, err := os.Stat(".secret"); os.IsNotExist(err) {
			showFlag = false
			localreport, err := enclave.GetLocalReport(nil, nil)
			if err != nil {
				fmt.Printf("get sgx localreport fail,  err: %v\r\n", err)
				return
			}
			encodedLocalreport, err := mbase.Encode(mbase.Base32, localreport)
			if err != nil {
				fmt.Printf("encode sgx localreport fail,  err: %v\r\n", err)
				return
			}
			dcRandumUrl := fmt.Sprintf("http://127.0.0.1:%d/teerandom?verifyreport=%s", dcport, encodedLocalreport)
			respBody, err := httpGet(dcRandumUrl)
			if err != nil {
				fmt.Print("request teerandom from server fail\r\n")
				continue
			}
			privKey, err := getRandomPrivKey()
			if err != nil {
				fmt.Printf("get  random privkey fail,  err: %v\r\n", err)
				continue
			}
			pub, _ := privKey.GetPublic().Raw()
			basePubkey, err := mbase.Encode(mbase.Base32, pub)
			if err != nil {
				return
			}
			report, err := enclave.VerifyLocalReport(respBody)
			if err != nil {
				fmt.Printf("teereport with teerandom verify fail,  err: %v\r\n", err)
				continue
			}
			signature, err := privKey.Sign(report.Data)
			if err != nil {
				fmt.Printf("sign teerandom fail,  err: %v\r\n", err)
				continue
			}
			localReport, err := enclave.GetLocalReport(signature, respBody)
			if err != nil {
				fmt.Printf("get sgx localreport with server response data fail,  err: %v\r\n", err)
				continue
			}
			encodedReport, err := mbase.Encode(mbase.Base32, localReport)
			if err != nil {
				fmt.Printf("encode sgx localreport with server response data  fail,  err: %v\r\n", err)
				continue
			}
			//参数：pubkey(验证teereport中report.data的数据为前面获取的随机数hash值的有效签名)，authSignature(验证teereport有效性），teereport(确保基于pubkey对应私钥对随机数的签名不被修改)
			dcSecretUrl := fmt.Sprintf("http://127.0.0.1:%d/secret", dcport)
			respBody, err = httpGet(dcSecretUrl, "pubkey="+basePubkey, "authSignature="+enclaveIdSignature, "teereport="+encodedReport)
			if err != nil {
				fmt.Printf("request secret fail,  err: %v\r\n", err)
				continue
			}
			var queryResult SecretQueryResult
			err = json.Unmarshal(respBody, &queryResult)
			if err != nil {
				fmt.Printf("unmarshal response data with secret fail,  err: %v,  respBody: %v \r\n", err, respBody)
				continue
			}
			report, err = enclave.VerifyLocalReport(queryResult.LocalReport)
			if err != nil {
				fmt.Printf("sgx localreport in response data with secret verify fail,  err: %v\r\n", err)
				continue
			}
			enclaveId := hex.EncodeToString(report.UniqueID) //获取不带0x开头的enclaveid的16进制字符串
			ok, err := commitPubkey.Verify([]byte(enclaveId), queryResult.EnclaveSignature)
			if err != nil || !ok {
				fmt.Printf("dcnode enclave signature verified  with commit pubkey fail, err: %v\r\n", err)
				continue
			}
			cpubkey, err := crypto.UnmarshalEd25519PublicKey(queryResult.Pubkey)
			if err != nil {
				fmt.Printf("UnmarshalEd25519PublicKey dcnode pubkey  fail, err: %v\r\n", err)
				continue
			}
			vPubkey := thread.NewLibp2pPubKey(cpubkey)
			signature = report.Data
			ok, err = vPubkey.Verify(queryResult.EncryptSecret, signature)
			if err != nil || !ok {
				fmt.Printf("signature that response as report.Data verified with dcnode pubkey fail,err: %v\r\n", err)
				continue
			}
			hIdentity := thread.NewLibp2pIdentity(privKey)
			plainSecret, err := hIdentity.Decrypt(context.Background(), queryResult.EncryptSecret)
			if err != nil {
				fmt.Printf("decrypt response secret   fail,  err: %v\r\n", err)
				continue
			}
			sealedSecretBytes, err := ecrypto.SealWithUniqueKey(plainSecret, nil)
			if err != nil {
				fmt.Printf("seal dcnode secret   fail,  err: %v\r\n", err)
				continue
			}
			err = os.WriteFile(".secret", sealedSecretBytes, 0)
			if err != nil {
				fmt.Printf("save sealed dcnode secret to file  fail,  err: %v\r\n", err)
				continue
			}
			SecretExistFlag = true
			showFlag = true
			fmt.Println("get dcnode secret  success")
		} else {
			SecretExistFlag = true
			if !showFlag {
				showFlag = true
				fmt.Println("node secret file exist")
			}
		}
	}
}

func httpGet(url string, args ...string) ([]byte, error) {
	client := http.Client{}
	if len(args) > 0 {
		url += "?" + strings.Join(args, "&")
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		newStr := buf.String()
		return nil, fmt.Errorf("http get err status,statuscode: %d,errmsg: %v", resp.StatusCode, newStr)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("err occur,no data get")
	}
	return body, nil
}

// 使用本地认证获取
func InitEnclaveId() (err error) {
	selfReport, err := enclave.GetSelfReport()
	if err != nil {
		fmt.Printf("InitEnclaveId Err:%v\n", err)
		return err
	}
	EnclaveId = hex.EncodeToString(selfReport.UniqueID)
	return
}

// 获取随机非对称加解密私钥
func getRandomPrivKey() (crypto.PrivKey, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return nil, err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, err
	}
	seed, err := schnorrkel.SeedFromMnemonic(mnemonic, "")
	if err != nil {
		return nil, err
	}
	secret := ed25519.NewKeyFromSeed(seed[:32])
	priv, err := crypto.UnmarshalEd25519PrivateKey([]byte(secret))
	if err != nil {
		return nil, err
	}
	return priv, nil

}

// 从配置文件获取技术委员会对当前升级辅助程序的enclaveid的授权签名
func initAuthSignatureFromConfigfile() bool {
	if _, err := os.Stat(authPath); err != nil {
		fmt.Printf("read auth file err,error: %v\n", err)
		return false
	}
	authSignature, err := os.ReadFile(authPath)
	if err != nil {
		fmt.Printf("read auth file err,error: %v\n", err)
		return false
	}
	enclaveIdSignature = string(authSignature)
	enclaveIdSignature = strings.Replace(enclaveIdSignature, " ", "", -1)
	enclaveIdSignature = strings.Replace(enclaveIdSignature, "\n", "", -1)
	_, authSignature, err = mbase.Decode(enclaveIdSignature)
	if err != nil {
		fmt.Printf("read config file err,can't decode signature,error: %v\n", err)
		return false
	}
	ok, err := commitPubkey.Verify([]byte(EnclaveId), authSignature)
	if err != nil || !ok {
		fmt.Printf("read config file err,can't verify signature,enclaveId: %s,error: %v\n", EnclaveId, err)
		return false
	}
	return true

}
