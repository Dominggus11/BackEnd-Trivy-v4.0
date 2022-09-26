package trivy

import (
	"os"
	"os/exec"
)

func TrivyScan(pathJson string, pathDocker string, filename string) {
	cmdUpload := exec.Command("trivy", "config", "-f", "json", "-o", "/home/rdam/Go-Project/trivy_v3/"+pathJson+"/resultsImage.json", filename)
	cmdUpload.Dir = pathDocker + "/"
	cmdUpload.Stdout = os.Stdout
	cmdUpload.Run()
}
