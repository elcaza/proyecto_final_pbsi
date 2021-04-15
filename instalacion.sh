#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Por favor corre como root"
  exit
fi

if ! command -v sudos &> /dev/null
then
    echo "Instalando sudo"
    apt update
    apt install sudo
fi

sudo apt update

sudo apt install -y build-essential
sudo apt install gnupg
wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -
echo "deb http://repo.mongodb.org/apt/debian buster/mongodb-org/4.4 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
sudo apt install -y mongodb-org
echo "mongodb-org hold" | sudo dpkg --set-selections
echo "mongodb-org-server hold" | sudo dpkg --set-selections
echo "mongodb-org-shell hold" | sudo dpkg --set-selections
echo "mongodb-org-mongos hold" | sudo dpkg --set-selections
echo "mongodb-org-tools hold" | sudo dpkg --set-selections
sudo systemctl daemon-reload
sudo systemctl enable mongod
sudo systemctl stop mongod
sudo systemctl restart mongod
sudo apt install -y python3-pip git nmap
wget https://chromedriver.storage.googleapis.com/88.0.4324.96/chromedriver_linux64.zip
unzip chromedriver_linux64.zip
sudo mv chromedriver /usr/bin/
sudo apt install -y testssl.sh
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install -y ./google-chrome-stable_current_amd64.deb
sudo pip3 install -r requeriments.txt
git clone https://github.com/tasos-py/Search-Engines-Scraper.git
cd Search-Engines-Scraper
sudo python3 setup.py install
sudo rm chromedriver_linux64.zip google-chrome-stable_current_amd64.deb