/*
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 * Licensed under GNU GPL v. 3
 */

var logto = "http://localhost:9131/";
//var logto = "http://leming.iitis.pl:9132/";
var cache = {};

var logit = function(str)
{
	var xhr;

	console.log(str);
	xhr = new XMLHttpRequest();
	xhr.open("GET", logto + str.replace('#', '?'), true);
	xhr.send();
};

logit("hello");

var reqdump = function(url, d, cache)
{
	var took = 0.0;
	var ts, ts2;

	/* skip cached responses */
	if (d.fromCache)
		return;

	/* skip if proxy */
	if (d.ip == "157.158.0.30")
		return;

	/* time when request was sent */
	if (cache && cache.timeStamp)
		ts = cache.timeStamp;
	else
		ts = d.timeStamp;

	/* time when first byte was received */
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
		d.type + "," +
		url.substr(0, 50) + "," +
		d.url.substr(0, 50)
	);
};

chrome.webRequest.onBeforeRequest.addListener(function(d)
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

	if (cache[d.requestId]) {
		if (!cache[d.requestId].headersReceivedOn)
			cache[d.requestId].headersReceivedOn = d.timeStamp;
	}
}, {
	urls: ["<all_urls>"]
}, [
]);

chrome.webRequest.onCompleted.addListener(function(d)
{
	if (d.url.substr(0, logto.length) == logto)
		return;

	var then = cache[d.requestId];

	/* try to get tab address */
	try {
		chrome.tabs.get(d.tabId, function(tab)
		{
			if (tab && tab.url)
				reqdump(tab.url, d, then);
			else
				reqdump(d.url, d, then);

			cache[d.requestId] = undefined;
		});
	} catch (e) {
		reqdump(d.url, d, then);
		cache[d.requestId] = undefined;
	}
}, {
	urls: ["<all_urls>"]
}, [
]);
