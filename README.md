# WebGopher
 
WebGopher  
Because we like to collect header, SSL/TLS, cert, and cookie flag information in a  
web application assessment but no one wants to do it...this tool fetches standard  
web assessment information for a list of URLs provided in an input file. The input  
file must contain one URL per line and the URLs must include their protocol (http  
or https).  
  
REQUIRES: ChromeDriver - https://sites.google.com/a/chromium.org/chromedriver/downloads  
                       - Add to PATH and update driver variable
   
***Usage***  
python3 webgopher.py &lt;inputfile&gt;
