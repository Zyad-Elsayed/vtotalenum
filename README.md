# vtotalenum
## subdomain enumeration via virustotal 

# installation 
+ git clone https://github.com/Zyad-Elsayed/vtotalenum.git
+ cd vtotalenum/
+ nano vtotalenum.go
+ replace xxxxx in line 76 by your virus total api
   ### to get virus total api key 
    - make account in virus-toal https://www.virustotal.com/gui/join-us 
    - then vist API key page from the upper rigt account icon https://www.virustotal.com/gui/user/{user_name}/apikey
    - after that copy the api key and add it to the script in " req.Header.Add " line

# guide 
+ ### to run it
   go run vtotalenum.go path_to_domain_list.txt
+ ### output 

   output is stored in virustotal_{domain}.txt file and would be saved in the same directory 
   
+ ### tip

   i recommend you to reuse it on the subdomain list generated for 2nd level subdomain enumeration 
