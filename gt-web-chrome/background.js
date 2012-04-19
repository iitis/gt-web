/*
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 * Licensed under GNU GPL v. 3
 */

var logto = "http://localhost:9131/";
var myip = "0.0.0.0";
var cache = {};

/*
 * Get my ip address
 */
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://jsonip.com/", true);
xhr.onreadystatechange = function() {
	if (xhr.readyState == 4) {
		var resp = JSON.parse(xhr.responseText);
		myip = resp.ip;

		logit("gt-web-chrome:" + myip);
		logit("columns:timestamp,reply,completion,remote-ip,tab-url,req-url");
	}
}
xhr.send();

var logit = function(str)
{
	var xhr;

//	console.log(str);
	xhr = new XMLHttpRequest();
	xhr.open("GET", logto + str, true);
	xhr.send();
};

var reqdump = function(url, d, cache)
{
	var took = 0.0;
	var ts, ts2;

	/* skip cached responses */
	if (d.fromCache)
		return;

	if (cache && cache.timeStamp)
		ts = cache.timeStamp;
	else
		ts = d.timeStamp;

	if (cache && cache.headersReceivedOn)
		ts2 = cache.headersReceivedOn;
	else
		ts2 = d.timeStamp;

	reply = Math.round((ts2 - ts)) / 1000;
	took = Math.round((d.timeStamp - ts)) / 1000;

	logit("" +
		(ts / 1000) + "," +
		reply + "," +
		took + "," +
		d.ip + "," +
		url.substr(0, 50) + "," +
		d.url.substr(0, 50)
	);
};

chrome.webRequest.onSendHeaders.addListener(function(d)
{
	if (d.url.substr(0, logto.length) == logto)
		return;

	cache[d.requestId] = d;
}, {
	urls: ["<all_urls>"]
}, [
]);

chrome.webRequest.onHeadersReceived.addListener(function(d)
{
	if (d.url.substr(0, logto.length) == logto)
		return;

	if (cache[d.requestId])
		cache[d.requestId].headersReceivedOn = d.timeStamp;
}, {
	urls: ["<all_urls>"]
}, [
]);

chrome.webRequest.onCompleted.addListener(function(d)
{
	if (d.url.substr(0, logto.length) == logto)
		return;

	var then = cache[d.requestId];

	try {
		chrome.tabs.get(d.tabId, function(tab)
		{
			if (tab && tab.url)
				reqdump(tab.url, d, then);
			else
				reqdump(d.url, d, then);
		});
	} catch (e) {
		reqdump(d.url, d, then);
	}

	cache[d.requestId] = undefined;
}, {
	urls: ["<all_urls>"]
}, [
]);
