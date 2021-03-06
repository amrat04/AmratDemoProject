-- MySQL Script generated by MySQL Workbench
-- Fri Jul 24 16:03:46 2020
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema mydb
-- -----------------------------------------------------
-- -----------------------------------------------------
-- Schema testloginmodule
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema testloginmodule
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `testloginmodule` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci ;
USE `testloginmodule` ;

-- -----------------------------------------------------
-- Table `testloginmodule`.`role`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `testloginmodule`.`role` ;

CREATE TABLE IF NOT EXISTS `testloginmodule`.`role` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NULL DEFAULT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 3
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;

LOCK TABLES `testloginmodule`.`role` WRITE;
/*!40000 ALTER TABLE `role` DISABLE KEYS */;
INSERT INTO `testloginmodule`.`role` VALUES (1,'ADMIN'),(2,'USER');
/*!40000 ALTER TABLE `role` ENABLE KEYS */;
UNLOCK TABLES;

-- -----------------------------------------------------
-- Table `testloginmodule`.`shortner`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `testloginmodule`.`shortner` ;

CREATE TABLE IF NOT EXISTS `testloginmodule`.`shortner` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `long_url` VARCHAR(255) NULL DEFAULT NULL,
  `unique_id` BIGINT NULL DEFAULT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 6
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;

LOCK TABLES `testloginmodule`.`shortner` WRITE;
/*!40000 ALTER TABLE `shortner` DISABLE KEYS */;
INSERT INTO `testloginmodule`.`shortner` VALUES (1,'http://test.com/abcd',20072108080979),(2,'https://www.mondetize.com/create-website',200721082430730),(3,'https://www.mondetize.com/create-website',200723081126726),(4,'https://www.mondetize.com/create-website',200723090949749),(5,'https://www.mondetize.com/create-website',200723093145745),(6,'https://timesofindia.indiatimes.com/',200724042359759);
/*!40000 ALTER TABLE `shortner` ENABLE KEYS */;
UNLOCK TABLES;

-- -----------------------------------------------------
-- Table `testloginmodule`.`user`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `testloginmodule`.`user` ;

CREATE TABLE IF NOT EXISTS `testloginmodule`.`user` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `password` VARCHAR(255) NULL DEFAULT NULL,
  `email` VARCHAR(45) NULL DEFAULT NULL,
  `first_name` VARCHAR(255) NULL DEFAULT NULL,
  `last_name` VARCHAR(50) NULL DEFAULT NULL,
  `image_url` VARCHAR(255) NULL DEFAULT NULL,
  `provider` VARCHAR(255) NULL DEFAULT NULL,
  `provider_id` VARCHAR(255) NULL DEFAULT NULL,
  `token` VARCHAR(255) NULL DEFAULT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 9
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;

LOCK TABLES `testloginmodule`.`user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `testloginmodule`.`user` VALUES (1,'$2a$10$e59rGaFvpijWXLh03j0aZOzBYQNrIRIjlB8sGwLvBL35fecblsW1m','amrat@gmail.com','Amrat','Chandnani',NULL,NULL,NULL,'eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxIiwiaWF0IjoxNTk1NDc1Mjg1LCJleHAiOjE1OTYzMzkyODJ9.fYsoAU0pFfTU6FaVmB7kIutPeG8qLmCb0Ye1v7YPJ26fwxrohUmYSUOfQZNwyWzUeP_EpghEJBRl7sEOhMg6Tw'),(2,'$2a$10$e59rGaFvpijWXLh03j0aZOzBYQNrIRIjlB8sGwLvBL35fecblsW1m','test@gmail.com','test first','test lastname',NULL,NULL,NULL,NULL),(3,'$2a$10$e59rGaFvpijWXLh03j0aZOzBYQNrIRIjlB8sGwLvBL35fecblsW1m','test3@gmail.com','Test3','Test3',NULL,NULL,NULL,NULL),(4,'$2a$10$e59rGaFvpijWXLh03j0aZOzBYQNrIRIjlB8sGwLvBL35fecblsW1m','test4@gmail.com','test4','test4',NULL,NULL,NULL,NULL),(5,'$2a$10$e59rGaFvpijWXLh03j0aZOzBYQNrIRIjlB8sGwLvBL35fecblsW1m','test5@gmail.com','test5','test5 last',NULL,NULL,NULL,NULL),(6,'$2a$10$e59rGaFvpijWXLh03j0aZOzBYQNrIRIjlB8sGwLvBL35fecblsW1m','test6@gmail.com','test 6','test 6 last',NULL,NULL,NULL,NULL),(7,'$2a$10$b.lYEbxNTkCwbFlNFB93.OBboCATF6y6URuWMfD4EqdF2k.E3/BZq','test7@gmail.com','test 7 ','test 7 last',NULL,NULL,NULL,NULL),(8,'$2a$10$OGQgznFn6D9N0XbqDvMa5OvWZ871hv7xjnr3uzDBDnVrY5Zo7D5uK','test8@gmail.com','test 8 ','test 8 last',NULL,NULL,NULL,NULL);
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;
-- -----------------------------------------------------
-- Table `testloginmodule`.`users_roles`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `testloginmodule`.`users_roles` ;

CREATE TABLE IF NOT EXISTS `testloginmodule`.`users_roles` (
  `user_id` BIGINT NOT NULL,
  `role_id` BIGINT NOT NULL,
  PRIMARY KEY (`user_id`, `role_id`),
  INDEX `FKt4v0rrweyk393bdgt107vdx0x` (`role_id` ASC) VISIBLE,
  CONSTRAINT `FKgd3iendaoyh04b95ykqise6qh`
    FOREIGN KEY (`user_id`)
    REFERENCES `testloginmodule`.`user` (`id`),
  CONSTRAINT `FKt4v0rrweyk393bdgt107vdx0x`
    FOREIGN KEY (`role_id`)
    REFERENCES `testloginmodule`.`role` (`id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;

LOCK TABLES `testloginmodule`.`user_roles` WRITE;
/*!40000 ALTER TABLE `user_roles` DISABLE KEYS */;
INSERT INTO `testloginmodule`.`user_roles` VALUES (1,1),(2,1),(4,1),(5,1),(6,1),(7,1),(8,1),(1,2),(4,2),(5,2),(6,2),(7,2),(8,2);
/*!40000 ALTER TABLE `user_roles` ENABLE KEYS */;
UNLOCK TABLES;

SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
