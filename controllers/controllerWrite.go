package controllers

import (
	"net/http"
	"trivy_v3/models"
	"trivy_v3/trivy"

	"github.com/gin-gonic/gin"
)

func FindCodes(c *gin.Context) {
	// Get model if exist
	// var dockerfiles []models.Dockerfiles
	// models.DB.Find(&dockerfiles)
	// c.JSON(http.StatusOK, gin.H{"data": dockerfiles})
	c.JSON(http.StatusOK, gin.H{
		"message": "Dalam Pengembangan !",
	})
}

func FindCode(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Dalam Pengembangan !",
	})
}

func PostCode(c *gin.Context) {
	//db := models.DB
	var input models.Dockerfiles
	if err := c.ShouldBind(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	pathFile := trivy.MkdirWriteFile()
	pathJson := trivy.MkdirWriteJson()
	file, err := c.FormFile("pathfile")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"message": "No file is received",
		})
		return
	}
	input.Pathfile = file.Filename
	c.SaveUploadedFile(file, pathFile+"/"+file.Filename)
	trivy.TrivyScan(pathJson, pathFile, input.Pathfile)

	//create Dockerfile
	dockerfile := models.Dockerfiles{
		Pathfile:  pathFile,
		PathJson:  pathJson,
		ProjectID: input.ProjectID,
	}
	models.DB.Create(&dockerfile)
	c.JSON(http.StatusOK, gin.H{
		"data": dockerfile,
	})
}

func UpdateCode(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Dalam Pengembangan !",
	})
}

func DeleteCode(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Dalam Pengembangan !",
	})
}
