/*
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 * Licensed under GNU GPL v. 3
 *
 * IDEAS
 * - local storage / upload service
 * - privacy?
 * - add timing from OnBeforeReceiveHeaders / similar
 */

var myip = "0.0.0.0";
var cache = {};

var logit = function(url, d, cache)
{
	var took = 0.0;
	var ts;

	/* skip cached responses */
	if (d.fromCache)
		return;

	if (cache && cache.timeStamp)
		ts = cache.timeStamp;
	else
		ts = d.timeStamp;

	took = Math.round((d.timeStamp - ts)) / 1000;

	console.log("" +
		(ts / 1000) + "," +
		d.ip + "," +
		took + "," +
		url.replace(/\?.*/, "")
	);
};

chrome.webRequest.onSendHeaders.addListener(function(d)
{
	cache[d.requestId] = d;
}, {
	urls: ["<all_urls>"]
}, [
]);

chrome.webRequest.onCompleted.addListener(function(d)
{
	var then = cache[d.requestId];

	try {
		chrome.tabs.get(d.tabId, function(tab)
		{
			if (tab && tab.url)
				logit(tab.url, d, then);
			else
				logit(d.url, d, then);
		});
	} catch (e) {
		logit(d.url, d, then);
	}

	cache[d.requestId] = undefined;
}, {
	urls: ["<all_urls>"]
}, [
]);

/*
 * Get my ip address
 */
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://jsonip.com/", true);
xhr.onreadystatechange = function() {
	if (xhr.readyState == 4) {
		var resp = JSON.parse(xhr.responseText);
		myip = resp.ip;

		console.log("gt-web-chrome loaded at " + myip);
	}
}
xhr.send();

