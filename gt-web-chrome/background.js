/*
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 * Licensed under GNU GPL v. 3
 *
 * IDEAS
 * - local storage / upload service
 * - privacy?
 * - add OnBeforeReceiveHeaders / similar
 */

var myip = "0.0.0.0";
var cache = {};

var logit = function(url, d, cache)
{
	var size_down = 0;
	var took = 0.0;
	var ts;

	/* skip cached responses */
	if (d.fromCache)
		return;

	/* find size */
	if (d.responseHeaders) {
		for (var i = 0; i < d.responseHeaders.length; ++i) {
			if (d.responseHeaders[i].name.toLowerCase() == 'content-length') {
				size_down = d.responseHeaders[i].value;
				break;
			}
		}
	}

	if (cache && cache.timeStamp)
		ts = cache.timeStamp;
	else
		ts = d.timeStamp;

	took = Math.round((d.timeStamp - ts)) / 1000;

	console.log("" +
		(ts / 1000) + "," +
		d.ip + "," +
		took + "," +
		size_down + "," +
		url.replace(/\?.*/, "") + "," +
		d.url.replace(/\?.*/, "")
	);
};

chrome.webRequest.onSendHeaders.addListener(function(d)
{
	cache[d.requestId] = d;
}, {
	urls: ["<all_urls>"]
}, [
	"requestHeaders"
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
	"responseHeaders"
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

