apt install golang -y <br/>
apt install git -y <br/>
apt update <br/>
apt install mysql-server -y <br/>
apt install libmysqld-dev -y <br/>
apt-get install gcc libmysqlclient-dev libmysqld-dev python-dev python-setuptools -y <br/>
apt install zmap -y <br/>
 <br/>
mysql -u root -p <br/>
> use mysql  <br/>
> update user set authentication_string=PASSWORD("tipDB@123") where User='root'; <br/>
> update user set plugin="mysql_native_password"; <br/>
> flush privileges; <br/>
> CREATE DATABASE `recon` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci; <br/>
<br/>

# zgrab
go get github.com/18121861183/zgrab2 <br/>
cd $GOPATH/src/github.com/18121861183/zgrab2 <br/>
go build <br/>
ln -s /root/go/src/github.com/zmap/18121861183/zgrab /usr/bin/zgrab2 <br/>

# ztag 
cd ./ztag <br/>
python setup.py build <br/>
python setup.py install <br/>
<br/>
<br/>
pip install -r requirements.txt <br/>
python manage.py makemigrations <br/>
python manage.py migrate <br/>
