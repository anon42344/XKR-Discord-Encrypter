/*

Use only chromestorage instead of both localstorage and chromestorage?

*/

'use strict';


var keysexists = false;
var url;
var serverurl;
var channelurl;
var urlarr ;
var code;

function saveChrome(key, value){
	var storage = chrome.storage.local;
	var v1 = key;
	storage.set({
	  [v1]: value // Will evaluate v1 as property name
	});
}

function removeChrome(key){
	chrome.storage.local.remove(key, function(){});
}

function loadChrome(key, f){
	var returnvalue;
	chrome.storage.local.get(null,function (obj){
		var mydata = obj;
		returnvalue = obj[key];
		f(returnvalue);
	});
	return returnvalue;
}

function receiveResult(resultsArray){
    console.log(resultsArray[0]);
}

function markTabAsInjected(tabs) {
	code = "document.getElementsByTagName('body')[0].setAttribute('data-injected', 'true');";
	chrome.tabs.executeScript(tabs[0].id, {code: code}, function() {}); // mark as injected
}

function markTabAsNotInjected(tabs) {
	code = "document.getElementsByTagName('body')[0].setAttribute('data-injected', 'false');";
	chrome.tabs.executeScript(tabs[0].id, {code: code}, function() {}); // mark as injected
}

/****************************

loadKeys
Tries to load keys from local storage when icon is clicked. 
When loaded, inejct.js is called, which is used for encryption and decryption. 
Chrome.storage is used just for sending parameters to inject.js. 
Other variables are stored in local storage.

****************************/
	

function loadKeys () {
	chrome.tabs.query({'active': true, 'lastFocusedWindow': true}, function (tabs) {
		url = (tabs[0].url).replace('https://','');
		urlarr = url.split("/");
		serverurl = urlarr[0] + "/" + urlarr[1] + "/" + urlarr[2];
		channelurl = url;	
		
		loadChrome(serverurl, function (serverkey) { 
			if(serverkey != undefined) {
				document.getElementById("server-key").value = serverkey; 
			}
		});	
		loadChrome(channelurl, function (channelkey) { 
			if(channelkey != undefined) {
				document.getElementById("channel-key").value = channelkey;
			}
		});	

				chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
					var path = chrome.extension.getURL('inject.js');
										var hasBeenInjected;
	
					//check if tab already has been injected
					code = "var returnvalue; if(document.getElementsByTagName('body')[0].getAttribute('data-injected') == 'true') { returnvalue='true'; } else {returnvalue='false';} returnvalue; ";
					chrome.tabs.executeScript(tabs[0].id, {code: code}, function(result) {

							hasBeenInjected = "" + result;

							if (hasBeenInjected == 'false') {
								chrome.tabs.executeScript(tabs[0].id, {file: '/inject.js'}, function() {}); // inject script
								markTabAsInjected(tabs);
							}
							
					}); 

					
				});
				
			
	});	
}	

loadKeys();
	
/****************************

setkeys
Reads channel/server keys from popup. 
Maps channel/server url to a encryption key. 
Stores this in local storage. 

****************************/

function setKeys() {
	var serverkey = (document.getElementById("server-key").value).replace(/\s/g, '');
	if(serverkey.length > 5) {
		saveChrome(serverurl, serverkey);

		var channelkey = (document.getElementById("channel-key").value).replace(/\s/g, '');
		//alert(loadChrome(serverurl) + " " + serverkey);
		//loadChrome(serverurl);
		if(channelkey != "") {
			if(channelkey.length > 5) {
				saveChrome(channelurl, channelkey);
			} else {
				alert("Your channel password is too short");
			}
		}
		document.getElementById("info").innerHTML = "Done. Refresh your page and click the icon to activate.";
	} else {
		alert("Your server password is too short");
	}
}


document.getElementById("setkeys").addEventListener("click", function(event) {
	setKeys();
}); 





/****************************

removekeys

****************************/

function removekeys() {
	
	try {
		removeChrome(serverurl)		
		removeChrome(channelurl);
		document.getElementById("info").innerHTML = "Done. Your keys has been deleted.";
	} catch(error) {
		alert("Error. Could not remove keys");
	}
	
}

document.getElementById("removekeys").addEventListener("click", function(event) {
	removekeys();
}); 