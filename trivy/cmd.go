package trivy

import (
	"os"
	"os/exec"
)

func TrivyScan(pathJson string, pathDocker string, filename string) {
	cmdUpload := exec.Command("trivy", "config", "-f", "json", "-o", "/home/roy/BackEnd-Trivy-v4.0/"+pathJson+"/resultsImage.json", filename)
	cmdUpload.Dir = pathDocker + "/"
	cmdUpload.Stdout = os.Stdout
	//fmt.Println(pathDocker)
	cmdUpload.Run()
}

// "pathfile": "FileDocker/FileUpload/3",
//"pathjson": "FileJson/FileUpload/3",
