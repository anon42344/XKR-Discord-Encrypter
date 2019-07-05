// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';


/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/

let page = document.body;

window.onload = function() {

var generatekeybuttons = page.getElementsByClassName("generatekey");

document.getElementById("generatekey").addEventListener("click", function(event) {	
	var obj = event.target;
	var id = obj.getAttribute("count");
	var textinputid = "randomkey" + id;
	var randompart = makeid(18);
	var e = document.getElementById("timeselector");
    var selecteditem = e.options[e.selectedIndex].value;
	var urls = document.getElementById("server1").value;
	var beforeencryption = randompart + "_" + urls + "_" + selecteditem;
	var finalkey = CryptoJS.AES.encrypt(beforeencryption, "xkrkey");
	document.getElementById(textinputid).value = finalkey;
	document.getElementById("beforeencryption").value = beforeencryption;
});
	
document.getElementById("showadvanced").addEventListener("click", function(event) {
	var styles = '.advancedstuff {display:block;}';
	var styleSheet = document.createElement("style");
	styleSheet.type = "text/css";
	styleSheet.innerText = styles;
	document.head.appendChild(styleSheet);
	document.getElementById("showadvanced").style.display = "none";	
	
	
});


}
	
	
function makeid(length) {
   var result           = '';
   var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
   var charactersLength = characters.length;
   for ( var i = 0; i < length; i++ ) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }
   return result;
}
