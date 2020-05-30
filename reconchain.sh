#!/bin/bash
#Thanks to @thecybermentor for the base script.

#Makes directory structure and some files.
function makeDirs {
    #Directory structure
    [ ! -d "$URL/recon" ] && mkdir -p $URL/recon/{scans,httprobe,potential_takeovers,wayback/{params,extensions}}
    #Make files
    [ ! -f "$URL/recon/httprobe/alive.txt" ] && touch $URL/recon/httprobe/alive.txt
    [ ! -f "$URL/recon/final.txt" ] && touch $URL/recon/final.txt #replaced by 'combined-subdomains.txt'
}

function badInput {
    echo "[-] ERROR: You must run with a url as parameter: $0 example.com"
    exit 1 #Maybe get more specific about the error code later.
}

#Assetfinder for finding subdomains.
#Decide how to best handle cases where these files already exist
function assetfinderAction {
    echo "[+] Harvesting subdomains with assetfinder..."
    assetfinder $URL >> $URL/recon/assetfinder-results.txt
    #Grep for subdomains belonging to our target
    cat $URL/recon/assetfinder-results.txt | grep $URL >> $URL/recon/assetfinder-subdomains.txt
    #remove the unfiltered results file
    rm $URL/recon/assetfinder-results.txt
}

#Amass for an additional check for subdomains
#Decide how to best handle cases where these files already exist
function amassAction {
    echo "[+] Double checking for subdomains with amass..."
    amass enum -d $URL >> $URL/recon/amass-results.txt
    #Make sure there are only unique entries
    sort -u $URL/recon/amass-results.txt  >> $URL/recon/amass-subdomains.txt
    #remove the  unfiltered results file
    rm $URL/recon/amass-results.txt
}

#Combines the subdomains found with assetfinder and amass into one file
#Decide how to best handle cases where these files already exist
function combineSubs {
    echo "[+] Combining the results of assetfinder and amass.."
    cat $URL/recon/assetfinder-subdomains.txt $URL/recon/amass-subdomains.txt >> $URL/recon/combined-results.txt
    echo "[+] Filtering combined results for duplicates..."
    cat $URL/recon/combined-results.txt | sort -u >> $URL/recon/combined-subdomains.txt
    rm $URL/recon/combined-results.txt
}

#Httprobe to help filter our subdomains to only the ones that are alive.
#Decide how to best handle cases where these files already exist
function httprobeAction {
    echo "[+] Probing for alive domains..."
    #The following should be used in the event that your DNS automatically resolves http to HTTPS
    #cat $URL/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $URL/recon/httprobe/a.txt
    cat $URL/recon/combined-subdomains.txt | httprobe >> $URL/recon/alive-subdomains.txt
}

#Subjack checks for potential subdomain takeover attacks
function subjackAction {
    echo "[+] Checking for possible subdomain takeover..."

    [ ! -f "$URL/recon/potential_takeovers/potential_takeovers.txt" ] && touch $URL/recon/potential_takeovers/potential_takeovers.txt

    subjack -w $URL/recon/alive-subdomains.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $URL/recon/potential_takeovers/potential_takeovers.txt
}

#Nmap Scan for interesting ports -- May be worth running safe nmap scripts against the targets as well
function nmapAction {
    echo "[+] Preparing subdomains file for nmap..."
    cp $URL/recon/alive-subdomains.txt $URL/recon/scans/subdomains-temp.txt

    cat $URL/recon/scans/subdomains-temp.txt | sed 's/https\?:\/\///' | sort -u >> $URL/recon/scans/nmap-targets.txt
    echo "[+] Scanning targets with Nmap..."
    nmap -iL $URL/recon/scans/nmap-targets.txt -T4 -oA $URL/recon/scans/scanned.txt
}

function waybackAction {

#Wayback Machine stuff
echo "[+] Scraping wayback data..."
cat $URL/recon/alive-subdomains.txt | waybackurls >> $URL/recon/wayback/wayback_output.txt
sort -u $URL/recon/wayback/wayback_output.txt

echo "[+] Pulling and compiling all possible params found in wayback data..."
cat $URL/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $URL/recon/wayback/params/wayback_params.txt
for line in $(cat $URL/recon/wayback/params/wayback_params.txt);do echo $line'=';done
echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..."

for line in $(cat $URL/recon/wayback/wayback_output.txt);do
	ext="${line##*.}"
	if [[ "$ext" == "js" ]]; then
		echo $line >> $URL/recon/wayback/extensions/js1.txt
		sort -u $URL/recon/wayback/extensions/js1.txt >> $URL/recon/wayback/extensions/js.txt
	fi
	if [[ "$ext" == "html" ]];then
		echo $line >> $URL/recon/wayback/extensions/jsp1.txt
		sort -u $URL/recon/wayback/extensions/jsp1.txt >> $URL/recon/wayback/extensions/jsp.txt
	fi
	if [[ "$ext" == "json" ]];then
		echo $line >> $URL/recon/wayback/extensions/json1.txt
		sort -u $URL/recon/wayback/extensions/json1.txt >> $URL/recon/wayback/extensions/json.txt
	fi
	if [[ "$ext" == "php" ]];then
		echo $line >> $URL/recon/wayback/extensions/php1.txt
		sort -u $URL/recon/wayback/extensions/php1.txt >> $URL/recon/wayback/extensions/php.txt
	fi
	if [[ "$ext" == "aspx" ]];then
		echo $line >> $URL/recon/wayback/extensions/aspx1.txt
		sort -u $URL/recon/wayback/extensions/aspx1.txt >> $URL/recon/wayback/extensions/aspx.txt
	fi
done

#Clean up files we used temporarily
rm $URL/recon/wayback/extensions/js1.txt
rm $URL/recon/wayback/extensions/jsp1.txt
rm $URL/recon/wayback/extensions/json1.txt
rm $URL/recon/wayback/extensions/php1.txt
rm $URL/recon/wayback/extensions/aspx1.txt
}

#Finally, take screenshots -- this needs to be replaced with gowitness.
function gowitnessAction {
    echo "[+] Running gowitness against all compiled domains..."
    #python3 EyeWitness/EyeWitness.py --web -f $URL/recon/httprobe/alive.txt -d $URL/recon/eyewitness --resolve
    gowitness file -s $URL/recon/alive-subdomains.txt -d $URL/recon
}

function main {
    #Make sure the url was provided and store in read-only variable 'URL'
    [ -z "$1" ] && badInput || readonly URL=$1

    #Note: There is currently no way to tell the script which scans to run/not run. Solution:
    #Comment out the actions you don't want the script to take (nmapAction, gowitnessAction, etc.)
    #until this feature is implemented. Careful not to comment out important functions like combineSubs.

    #Actions
    makeDirs #Important!
    assetfinderAction
    amassAction
    combineSubs #Important!
    httprobeAction
    subjackAction
    nmapAction
    waybackAction
    gowitnessAction

    #Confirm everything finished to user
    echo "[i] Done! Check current directory for results."

}

#Call our main function with the parameter this script was ran with
main $1
