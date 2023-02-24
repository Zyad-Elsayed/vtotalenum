# vtotalenum
## subdomain enumeration via virustotal 
# prerequisite 
you have to install go language first 
   + update your system `sudo apt update `
   + install go packages 
       > sudo apt install gccgo-go
       
       > sudo apt-get install golang-go

# installation 
+ git clone https://github.com/Zyad-Elsayed/vtotalenum.git
+ cd vtotalenum/
+ nano vtotalenum.go
+ replace xxxxx in line 76 by your virusTotal API
   ### to get virusTotal api key 
    - make a virus-total account `https://www.virustotal.com/gui/join-us` 
    - then vist API key page from the upper rigt account icon `https://www.virustotal.com/gui/user/{user_name}/apikey`
    - after that copy the API key and add it to the script in `req.Header.Add` line

# guide 
+ ### to run it
   go run vtotalenum.go path_to_domain_list.txt
+ ### output 

   output is stored in virustotal_{domain}.txt file and would be saved in the same directory 
   
+ ### tip

   i recommend you to reuse it on the generated subdomain list for 2nd level subdomain enumeration
