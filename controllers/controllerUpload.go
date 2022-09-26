package controllers

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"trivy_v3/models"
	"trivy_v3/trivy"

	"github.com/gin-gonic/gin"
)

type BindFile struct {
	File      *multipart.FileHeader `form:"file"`
	Pathfile  string                `form:"pathfile"`
	PathJson  string                `form:"pathjson"`
	ProjectID int                   `form:"projectid"`
}

func FindDockers(c *gin.Context) {
	var dockerfiles []models.Dockerfiles
	models.DB.Find(&dockerfiles)

	c.JSON(http.StatusOK, gin.H{"data": dockerfiles})
}

func PostDockerfile(c *gin.Context) {
	db := models.DB
	router := gin.Default()
	router.MaxMultipartMemory = 8 << 20
	var bindFile BindFile
	// var input models.Dockerfiles
	if err := c.ShouldBind(&bindFile); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	pathFile := trivy.MkdirUploadFile()
	pathJson := trivy.MkdirUploadJson()
	file, err := c.FormFile("file")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
		return
	}

	//create Dockerfile
	dockerfile := models.Dockerfiles{
		Pathfile:  pathFile,
		PathJson:  pathJson,
		ProjectID: bindFile.ProjectID,
	}
	fmt.Println(bindFile.ProjectID)
	var project models.Projects
	if err := db.Where("id = ?", bindFile.ProjectID).First(&project).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Project Tidak Tersedia !!!"})
		return
	}

	bindFile.Pathfile = file.Filename
	c.SaveUploadedFile(file, pathFile+"/"+file.Filename)
	trivy.TrivyScan(pathJson, pathFile, bindFile.Pathfile)

	models.DB.Create(&dockerfile)

	c.JSON(http.StatusOK, gin.H{
		"data": dockerfile,
	})
}

func FindDocker(c *gin.Context) {
	db := models.DB
	// Get model if exist
	var dockerfile models.Dockerfiles
	if err := db.Where("id = ?", c.Param("id")).First(&dockerfile).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": dockerfile})
}

func UpdateDocker(c *gin.Context) {
	db := models.DB
	// Get model if exist
	var input models.Dockerfiles
	if err := db.Where("id = ?", c.Param("id")).First(&input).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}

	pathFile := input.Pathfile
	pathJson := input.PathJson
	file, err := c.FormFile("pathfile")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"message": "No file is received",
		})
		return
	}
	filename := file.Filename
	c.SaveUploadedFile(file, pathFile+"/"+file.Filename)
	trivy.TrivyScan(pathJson, pathFile, filename)
	dockerfile := models.Dockerfiles{
		Pathfile:  pathFile,
		PathJson:  pathJson,
		ProjectID: input.ProjectID,
	}
	//db.Updates(&dockerfile)
	db.Model(&input).Updates(dockerfile)
	c.JSON(http.StatusOK, gin.H{
		"data": input,
	})

}

func DeleteDocker(c *gin.Context) {
	db := models.DB
	// Get model if exist
	var input models.Dockerfiles
	if err := db.Where("id = ?", c.Param("id")).First(&input).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}
	pathFile := input.Pathfile
	pathJson := input.PathJson

	os.RemoveAll(pathFile)
	os.RemoveAll(pathJson)
	db.Delete(&input)

	c.JSON(http.StatusOK, gin.H{
		"data": "Deleted",
	})
}

func GetJson(c *gin.Context) {
	db := models.DB
	// Get model if exist
	var input models.Dockerfiles
	if err := db.Where("id = ?", c.Param("id")).First(&input).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record not found!"})
		return
	}
	pathJson := input.PathJson + "/resultsImage.json"
	file, _ := os.Open(pathJson)
	defer file.Close()

	fileContent, _ := io.ReadAll(file)

	c.String(http.StatusOK, string(fileContent))
}
