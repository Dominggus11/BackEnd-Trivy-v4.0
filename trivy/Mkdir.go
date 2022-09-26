package trivy

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

func MkdirUploadFile() string {
	folder := 1
	pathFolder := "FileDocker/FileUpload/"
	for i := 1; i < 10; i++ {
		_, err := os.Stat(pathFolder + strconv.Itoa(folder))
		if err == nil {
			folder = folder + 1
		} else {
			fmt.Println(pathFolder + strconv.Itoa(folder))
			cmdUpload := exec.Command("mkdir", pathFolder+strconv.Itoa(folder))
			cmdUpload.Stdout = os.Stdout
			cmdUpload.Run()
			break
		}
	}
	return pathFolder + strconv.Itoa(folder)
}

func MkdirWriteFile() string {
	folder := 1
	pathFolder := "FileDocker/FileWrite/"
	for i := 1; i < 10; i++ {
		_, err := os.Stat(pathFolder + strconv.Itoa(folder))
		if err == nil {
			folder = folder + 1
		} else {
			cmdUpload := exec.Command("mkdir", pathFolder+strconv.Itoa(folder))
			cmdUpload.Stdout = os.Stdout
			cmdUpload.Run()
			break
		}
	}
	return pathFolder + strconv.Itoa(folder)
}

func MkdirWriteJson() string {
	folder := 1
	pathFolder := "FileJson/FileWrite/"
	for i := 1; i < 10; i++ {
		_, err := os.Stat(pathFolder + strconv.Itoa(folder))
		if err == nil {
			folder = folder + 1
		} else {
			cmdUpload := exec.Command("mkdir", pathFolder+strconv.Itoa(folder))
			cmdUpload.Stdout = os.Stdout
			cmdUpload.Run()
			break
		}
	}
	return pathFolder + strconv.Itoa(folder)
}

func MkdirUploadJson() string {
	folder := 1
	pathFolder := "FileJson/FileUpload/"
	for i := 1; i < 10; i++ {
		_, err := os.Stat(pathFolder + strconv.Itoa(folder))
		if err == nil {
			folder = folder + 1
		} else {
			cmdUpload := exec.Command("mkdir", pathFolder+strconv.Itoa(folder))
			cmdUpload.Stdout = os.Stdout
			cmdUpload.Run()
			break
		}
	}
	return pathFolder + strconv.Itoa(folder)
}
