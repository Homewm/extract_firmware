package main
import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"./gpool"
)

//下载固件的存放位置，其路径下存放了很多厂商目录，厂商目录下才是存放多个固件的位置
//const inputPath = "/home/ubuntu/zgd/golangenv/src/extract_firmware/firmDir"
//const inputPath = "/home/ubuntu/disk/hdd_1/zgd/yunan_firmware/firmDir3"
const inputPath = "/home/ubuntu/disk/hdd_3/zgd/firmwares_deal_zgd"

//解压固件后存放的位置
//const outputPath = "/home/ubuntu/zgd/golangenv/src/extract_firmware/output"
//const outputPath = " /home/ubuntu/disk/hdd_1/zgd/yunan_firmware/output3"
const outputPath = "/home/ubuntu/disk/hdd_3/zgd/firmwares_extract_zgd/output/firmwareExtracted_vendor"

//固件解压和分析脚本存放的位置。shell脚本里使用到了tromer程序
//const extractScript = "/usr/local/firmware-association/bin/Extract.sh"
const extractScript = "/home/ubuntu/zgd/golangenv/src/extract_firmware/ExtractScript/Extract.sh"


//获取指定路径下的厂商名列表，返回厂商列表
func getVendorName(inputPath string, vendors []string) ([]string, error) {

	rd, err := ioutil.ReadDir(inputPath)
	if err != nil {
		fmt.Println("read dir fail:", err)
	} else {
		for _, fi := range rd {
			if fi.IsDir(){
				vendors = append(vendors, fi.Name())
			}
		}}
	return vendors, err
}


//输出文件路径创建
func outputDir(vendor string) string {
	vendorPath :=  outputPath + "/" + vendor
	_, err := os.Stat(vendorPath)
	//check dir
	if err == nil {
		fmt.Println("The path is exist!", vendorPath)
	}else {
		fmt.Println("The path is not exists, please create it!", vendorPath)
		err := os.MkdirAll(vendorPath, 0711)
		if err != nil {
			log.Println("Error create the directory", vendorPath)
			log.Println(err)
		}
	}
	return vendorPath

}


//获取厂商文件夹下的对应的文件，返回每个厂商的列表
func getVendorFiles(vendor string) []string {
	var filesPath_list []string
	fileDir := inputPath + "/" + vendor
	_, err := os.Stat(fileDir)
	if err == nil{
		files, _ := ioutil.ReadDir(fileDir)
		for _, file := range files{
			if file.IsDir(){
				continue
			}else {
				firmpath := fileDir + "/" + file.Name()
				filesPath_list = append(filesPath_list, firmpath)
				}
			}
		}
	return filesPath_list
	}



//判断厂商解分析脚本是否存在
func getExtractScript()(string, error){
	_, err := os.Stat(extractScript)
	if err != nil && os.IsNotExist(err) {
		return "", err
	}
	return extractScript, nil
}


//执行解压缩脚本程序进行文件解压
func Task(extractScript, firmwarePath, vendorPath string, pool *gpool.Pool){
	defer pool.Done()
	cmd := exec.Command(extractScript, firmwarePath, vendorPath, ">/dev/null 2>&1")
	err := cmd.Run()
	if err != nil {
		fmt.Println(err)
	}
	log.Println("done->", firmwarePath)
}


func main() {
	//遍历所有需要解压的厂商，返回厂商名
	var vendors []string
	vendors, _ = getVendorName(inputPath, vendors)

	pool := gpool.New(runtime.NumCPU() + 1)

	for _, vendor := range vendors{
		//创建需要解压文件厂商对应的所有路径，无返回值
		vendorPath := outputDir(vendor)

		//遍历每个厂商下所有的文件，返回每个厂商的文件列表
		filesPath_list := getVendorFiles(vendor)

		//判断解压脚本是否存在，如果不存在终止程序
		extractScript, err:= getExtractScript()

		if err != nil {
			fmt.Println("解压分析脚本程序不存在")
			return
		}else {

			for _, firmwarePath := range filesPath_list{
				pool.Add(1)
				go Task(extractScript, firmwarePath, vendorPath, pool)
			}
			pool.WaitAll()

		 }
	}
}

