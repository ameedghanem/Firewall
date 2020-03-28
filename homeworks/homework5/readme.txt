In order to run the firewall we do the following:
enter the module directory -> make -> sudo insmod hw5secws.ko 

in order to load rules we run the main.py file in user directory:
sudo python main.py load_rules <rules_path>

for runnign the smtp proxy we run the smtp_proxy.py file:
sudo python3 smtp_proxy.py
then if we sent a mail through the smtp protcol we analyse the packet
content and checks whether the message is a C code or not.

in order to block the vulnerability that i was supposed to:
we run firstly the http server:
sudo python3 http_proxy.py (exists the http folder) 
i detects an a attack by input validation