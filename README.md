# Web_Attacks_Investigations

# Case # 1 : Investigating a possible  SQL attack

Web server WAF detected an SQL Injection payload, triggering an alert on SIEM.
	
	Feb, 25, 2022, 11:34 AM
	Rule :SOC165 - Possible SQL Injection Payload Detected
	Hostname :WebServer1001
	Destination IP Address :172.16.17.18
	Source IP Address :167.99.169.17
	HTTP Request Method :GET
	Requested URL :https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-
	User-Agent :Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
	Alert Trigger Reason :
	Requested URL Contains OR 1 = 1
	Device Action :Allowed
	
 
Filtering HTTPS traffic on SIEM based on the source IP address to investigate all the requests.  Traffic was initiated from the internet to the inside network.
	
![image](https://github.com/user-attachments/assets/70e19b77-f0fb-4b8f-be2f-e0239b71322a)



 
Checking the "Requests URL" parameters  sent to the web server on all requests coming from this IP - 167.99.169.17

![image](https://github.com/user-attachments/assets/9f4b08a3-4e7e-4ed2-b474-04b55215eb3e)


Decoding the URL in CyberChef confirms the SQL injection attack on the following three requests
	
https://172.16.17.18/search/?q=' OR '1
https://172.16.17.18/search/?q=' OR 'x'='x
https://172.16.17.18/search/?q=1' ORDER BY 3--+

![image](https://github.com/user-attachments/assets/41cd166e-c744-44ae-b4d4-33c2b6dd1056)

	
	
 

Also, Checking the source IP on 'VirusTotal' confirms that the IP is malicious 
	

![image](https://github.com/user-attachments/assets/79ded74e-aa8a-4fed-bc22-3bd0b74f73bb)
	



Now checking the HTTP response to determine if the attack was successful and if escalation is required. The web server has responded with status response 500, confirming the attack was unsuccessful. Hence, no escalation was carried out. 
	
![image](https://github.com/user-attachments/assets/02549816-e9b1-4262-bf74-6b2d684ff2e2)



Extracted artifacts

![image](https://github.com/user-attachments/assets/b79db505-f190-469d-aac4-873e635126ad)





# Investigation Report:

-An SQL attack was detected on the Apache web server (webserver101). 
-Following analysis of the SIEM logs, the first attack was initiated from source IP address 167.99.169.17 on Feb 25, 2022, at 11:32 AM. 
-Traffic was initiated from Outside (Internet) to the  Internal network.
-Checking logs and source user-agent did not confirm if the attack was part of simulated pen testing.  
-VirusTotal also flags the source IP address as malicious.  Cisco Talos did not provide any report on this IP.
-Upon decoding the requests sent to the web server in CyberChef, the following SQL injection combinations were observed:
	
https://172.16.17.18/search/?q=' OR '1
https://172.16.17.18/search/?q=' OR 'x'='x
https://172.16.17.18/search/?q=1' ORDER BY 3--+

-The attacker used the user agent "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1."
-The server's " HTTP Response Status" of 500 confirms that the SQL attack was unsuccessful. Hence, no escalation was required. 

[##############################################################################]


# Case # 2 : Investigating a possible XSS attack

Web server WAF detected  Javascript Code in the URL and sent the below alert to the SIEM.


	EventID:116
	Event Time :Feb, 26, 2022, 06:56 PM
	Rule : SOC166 - Javascript Code Detected in Requested URL
	Level : Security Analyst
	Hostname :WebServer1002
	Destination IP Address :172.16.17.17
	Source IP Address :112.85.42.13
	HTTP Request Method :GET
	Requested URL :
	https://172.16.17.17/search/?q=<$script>javascript:$alert(1)<$/script>
	User-Agent :Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
	Alert Trigger Reason :Javascript code detected in URL
	Device Action :Allowed


Filtering out HTTPS traffic on SIEM based on the source IP address to investigate all the requests.  
![image](https://github.com/user-attachments/assets/5242bad6-935e-4c66-8b40-1dab031238c6)


Traffic was initiated from the internet to the inside network. I checked the reputation of the source IP address on VirusTotal and Talos. IP comes from China and has a 'poor' reputation.
![image](https://github.com/user-attachments/assets/e65f3ef2-40df-4681-9829-6c675cba23e5)

![image](https://github.com/user-attachments/assets/326b44b2-a852-4173-ab51-555c3d51aa17)


Check each request's "Requests URL" parameters originating from IP 112.85.42.13. The first XSS payload was sent to the web server on Feb 26, 2022, at 06:46 PM, as shown below. 
![image](https://github.com/user-attachments/assets/a80f2318-b747-4840-8507-996915ecd6ba)

Decode the first URL query parameter on CyberChef.
![image](https://github.com/user-attachments/assets/fc944784-7008-4605-9519-83c840295a31)

Analysing and decoding subsequent requests show three more malicious Javascript injections into the query strings below. 
	
https://172.16.17.17/search/?q=<$script>$for((i)in(self))eval(i)(1)<$/script>
https://172.16.17.17/search/?q=<$svg><$script%20?>$alert(1)
https://172.16.17.17/search/?q=<$script>$for((i)in(self))eval(i)(1)<$/script>

Next, check the EDR log to see if XSS attacks were successfully executed on the web server.  There was no record of the successful execution of the commands on the server.

Checking the response error code 302 also confirms that the attack was unsuccessful; hence no escalation was required.

![image](https://github.com/user-attachments/assets/6d552400-289a-471b-a867-a7caef97f9c9)


[##############################################################################]

# Case # 3 : Investigating a possible  IDOR (Insecure Direct Object Reference) attack

Web server WAF detected a possible IDOR attack, triggering an alert on SIEM.

	EventID :119
	Event Time :Feb, 28, 2022, 10:48 PM
	Rule :SOC169 - Possible IDOR Attack Detected
	Level :Security Analyst
	Hostname :WebServer1005
	Destination IP Address :172.16.17.15
	Source IP Address :134.209.118.137
	HTTP Request Method :POST
	Requested URL :https://172.16.17.15/get_user_info/
	User-Agent :Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)
	Alert Trigger Reason :consecutive requests to the same page
	Device Action :Allowed

Filtering HTTPS traffic on SIEM based on the source IP address to investigate all the requests.  Traffic was initiated from the internet to the inside network.

![image](https://github.com/user-attachments/assets/ad162cbd-34a0-46ed-ba14-d4452307b0f5)

Checking the "Requests URL" parameters  sent to the web server on all requests coming from this IP - 134.209.118.137. 
Also searching for "user_id" parameter supplied as part of the POST method confirms attacker has tried to gain lateral access using different user ids . The following 'user_id' are submitted to the web server 

- user_id=1
- user_id=2
- user_id=3
- user_id=5
  
![image](https://github.com/user-attachments/assets/887ec2d2-4d19-4ed2-86c5-78ebec039366)

Webserver has responded with status code 200 confirming the IDOR attack was successfully executed on the web server. case has been escalated for further investigation.  

Extracted artifacts

![image](https://github.com/user-attachments/assets/06d4322c-b566-470a-b1e4-96575177eb4d)




