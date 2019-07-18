apt install golang -y
apt install git -y
apt update
apt install mysql-server -y
apt install libmysqld-dev -y
apt-get install gcc libmysqlclient-dev libmysqld-dev python-dev python-setuptools -y
apt install zmap -y

mysql -u root -p
> use mysql 
> update user set authentication_string=PASSWORD("tipDB@123") where User='root';
> update user set plugin="mysql_native_password";
> flush privileges;
> CREATE DATABASE `recon` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;


# zgrab
go get github.com/zmap/zgrab2
cd $GOPATH/src/github.com/zmap/zgrab2
go build
ln -s /root/go/src/github.com/zmap/zgrab2/zgrab /usr/bin/zgrab2

# ztag 
cd ./ztag
python setup.py build
python setup.py install


pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
