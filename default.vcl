vcl 4.0;

import std;

backend default {
  # Location of PageSpeed server.
  .host = "127.0.0.1";
  .port = "8000";
 .max_connections = 250;
    .connect_timeout = 300s;
    .first_byte_timeout = 300s;
    .between_bytes_timeout = 300s;
}
acl purge {
  "localhost";
  "127.0.0.1";
}

sub generate_user_agent_based_key {

    set req.http.default_ps_capability_list_for_large_screens = "LargeScreen.SkipUADependentOptimizations:";
    set req.http.default_ps_capability_list_for_small_screens = "TinyScreen.SkipUADependentOptimizations:";

    set req.http.PS-CapabilityList = req.http.default_ps_capability_list_for_large_screens;


    if (req.http.User-Agent ~ "(?i)Chrome/|Firefox/|MSIE |Safari|Wget") {
      set req.http.PS-CapabilityList = "ll,ii,dj:";
    }

    if (req.http.User-Agent ~
        "(?i)Chrome/[2][3-9]+\.|Chrome/[[3-9][0-9]+\.|Chrome/[0-9]{3,}\.") {
      set req.http.PS-CapabilityList = "ll,ii,dj,jw,ws:";
    }

    if (req.http.User-Agent ~ "(?i)Firefox/[1-2]\.|MSIE [5-8]\.|bot|Yahoo!|Ruby|RPT-HTTPClient|(Google \(\+https\:\/\/developers\.google\.com\/\+\/web\/snippet\/\))|Android|iPad|TouchPad|Silk-Accelerated|Kindle Fire") {
      set req.http.PS-CapabilityList = req.http.default_ps_capability_list_for_large_screens;
    }

    if (req.http.User-Agent ~ "(?i)Mozilla.*Android.*Mobile*|iPhone|BlackBerry|Opera Mobi|Opera Mini|SymbianOS|UP.Browser|J-PHONE|Profile/MIDP|portalmmm|DoCoMo|Obigo|Galaxy Nexus|GT-I9300|GT-N7100|HTC One|Nexus [4|7|S]|Xoom|XT907") {
      set req.http.PS-CapabilityList = req.http.default_ps_capability_list_for_small_screens;
    }
    unset req.http.default_ps_capability_list_for_large_screens;
    unset req.http.default_ps_capability_list_for_large_screens;
}


sub vcl_recv {


  call generate_user_agent_based_key;

  # We want to support beaconing filters, i.e., one or more of inline_images,
  # lazyload_images, inline_preview_images or prioritize_critical_css are
  # enabled. We define a placeholder constant called ps_should_beacon_key_value
  # so that some percentages of hits and misses can be sent to the backend
  # with this value used for the PS-ShouldBeacon header to force beaconing.
  # This value should match the value of the DownstreamCacheRebeaconingKey
  # pagespeed directive used by your backend server.
  # WARNING: Do not use "random_rebeaconing_key" for your configuration, but
  # instead change it to something specific to your site, to keep it secure.
  set req.http.ps_should_beacon_key_value = "random_rebeaconing_key";
  # Incoming PS-ShouldBeacon headers should not be allowed since this will allow
  # external entities to force the server to instrument pages.
  unset req.http.PS-ShouldBeacon;

  # Block 3d: Verify the ACL for an incoming purge request and handle it.
  if (req.method == "PURGE") {
    if (!client.ip ~ purge) {
      return (synth(405,"Not allowed."));
    }
    return (purge);
  }
  # Blocks which decide whether cache should be bypassed or not go here.
  # Block 5a: Bypass the cache for .pagespeed. resource. PageSpeed has its own
  # cache for these, and these could bloat up the caching layer.
  if (req.url ~ "\.pagespeed\.([a-z]\.)?[a-z]{2}\.[^.]{10}\.[^.]+") {
    # Skip the cache for .pagespeed. resource.  PageSpeed has its own
    # cache for these, and these could bloat up the caching layer.
    return (pass);
  }
  # Block 5b: Only cache responses to clients that support gzip.  Most clients
  # do, and the cache holds much more if it stores gzipped responses.
  if (req.http.Accept-Encoding !~ "gzip") {
    return (pass);
  }

	set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");

	# Allow purging from ACL
	if (req.method == "PURGE") {
		# If not allowed then a error 405 is returned
		if (!client.ip ~ purge) {
			return(synth(405, "This IP is not allowed to send PURGE requests."));
		}	
		# If allowed, do a cache_lookup -> vlc_hit() or vlc_miss()
		return (purge);
	}

	# Post requests will not be cached
	if (req.http.Authorization || req.method == "POST") {
		return (pass);
	}

	# --- Wordpress specific configuration
	
	# Did not cache the RSS feed
	if (req.url ~ "/feed") {
		return (pass);
	}

	# Blitz hack
        if (req.url ~ "/mu-.*") {
                return (pass);
        }

	
	# Did not cache the admin and login pages
	if (req.url ~ "/wp-(login|admin)") {
		return (pass);
	}

	# Remove the "has_js" cookie
	set req.http.Cookie = regsuball(req.http.Cookie, "has_js=[^;]+(; )?", "");

	# Remove any Google Analytics based cookies
	set req.http.Cookie = regsuball(req.http.Cookie, "__utm.=[^;]+(; )?", "");

	# Remove the Quant Capital cookies (added by some plugin, all __qca)
	set req.http.Cookie = regsuball(req.http.Cookie, "__qc.=[^;]+(; )?", "");

	# Remove the wp-settings-1 cookie
	set req.http.Cookie = regsuball(req.http.Cookie, "wp-settings-1=[^;]+(; )?", "");

	# Remove the wp-settings-time-1 cookie
	set req.http.Cookie = regsuball(req.http.Cookie, "wp-settings-time-1=[^;]+(; )?", "");

	# Remove the wp test cookie
	set req.http.Cookie = regsuball(req.http.Cookie, "wordpress_test_cookie=[^;]+(; )?", "");

	# Are there cookies left with only spaces or that are empty?
	if (req.http.cookie ~ "^ *$") {
		    unset req.http.cookie;
	}
	
	# Cache the following files extensions 
	if (req.url ~ "\.(css|js|png|gif|jp(e)?g|swf|ico)") {
		unset req.http.cookie;
	}

	# Normalize Accept-Encoding header and compression
	# https://www.varnish-cache.org/docs/3.0/tutorial/vary.html
	if (req.http.Accept-Encoding) {
		# Do no compress compressed files...
		if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") {
			   	unset req.http.Accept-Encoding;
		} elsif (req.http.Accept-Encoding ~ "gzip") {
		    	set req.http.Accept-Encoding = "gzip";
		} elsif (req.http.Accept-Encoding ~ "deflate") {
		    	set req.http.Accept-Encoding = "deflate";
		} else {
			unset req.http.Accept-Encoding;
		}
	}

	# Check the cookies for wordpress-specific items
	if (req.http.Cookie ~ "wordpress_" || req.http.Cookie ~ "comment_") {
		return (pass);
	}
	if (!req.http.cookie) {
		unset req.http.cookie;
	}
	
	# --- End of Wordpress specific configuration

	# Did not cache HTTP authentication and HTTP Cookie
	if (req.http.Authorization || req.http.Cookie) {
		# Not cacheable by default
		return (pass);
	}

	# Cache all others requests
	return (hash);
}

sub vcl_hit {
  # Send 5% of the HITs to the backend for instrumentation.
  if (std.random(0, 100) <= 5) {
    set req.http.PS-ShouldBeacon = req.http.ps_should_beacon_key_value;
    return (pass);
  }
}

sub vcl_miss {
  # Send 25% of the MISSes to the backend for instrumentation.
  if (std.random(0, 100) <= 25) {
    set req.http.PS-ShouldBeacon = req.http.ps_should_beacon_key_value;
    return (pass);
  }
}
 
sub vcl_pipe {
	return (pipe);
}
 
sub vcl_pass {
	return (fetch);
}
 
# The data on which the hashing will take place
sub vcl_hash {

  hash_data(req.http.PS-CapabilityList);

 	hash_data(req.url);
 	if (req.http.host) {
     	hash_data(req.http.host);
 	} else {
     	hash_data(server.ip);
 	}

	# If the client supports compression, keep that in a different cache
    	if (req.http.Accept-Encoding) {
        	hash_data(req.http.Accept-Encoding);
	}
     


	return (lookup);
}
 
# This function is used when a request is sent by our backend (Nginx server)
sub vcl_backend_response {
	# Remove some headers we never want to see
	unset beresp.http.Server;
	unset beresp.http.X-Powered-By;

	# For static content strip all backend cookies
	if (bereq.url ~ "\.(css|js|png|gif|jp(e?)g)|swf|ico") {
		unset beresp.http.cookie;
	}

	# Only allow cookies to be set if we're in admin area
	if (beresp.http.Set-Cookie && bereq.url !~ "^/wp-(login|admin)") {
        	unset beresp.http.Set-Cookie;
    	}

	# don't cache response to posted requests or those with basic auth
	if ( bereq.method == "POST" || bereq.http.Authorization ) {
        	set beresp.uncacheable = true;
		set beresp.ttl = 120s;
		return (deliver);
    	}
 
    	# don't cache search results
	if ( bereq.url ~ "\?s=" ){
		set beresp.uncacheable = true;
                set beresp.ttl = 120s;
                return (deliver);
	}
    
	# only cache status ok
	if ( beresp.status != 200 ) {
		set beresp.uncacheable = true;
                set beresp.ttl = 120s;
                return (deliver);
	}

	# A TTL of 24h
	set beresp.ttl = 24h;
	# Define the default grace period to serve cached content
	set beresp.grace = 30s;
	
	 if (beresp.http.Content-Type ~ "text/html") {
     # Hide the upstream cache control headers.
     unset beresp.http.ETag;
     unset beresp.http.Last-Modified;
     unset beresp.http.Cache-Control;
     # Add no-cache Cache-Control header for html.
     set beresp.http.Cache-Control = "no-cache, max-age=0";
   }

   return (deliver);

}
 
# The routine when we deliver the HTTP request to the user
# Last chance to modify headers that are sent to the client
sub vcl_deliver {
	if (obj.hits > 0) { 
		set resp.http.X-Cache = "cached";
	} else {
		set resp.http.x-Cache = "uncached";
	}

	# Remove some headers: PHP version
	unset resp.http.X-Powered-By;

	# Remove some headers: Apache version & OS
	unset resp.http.Server;

	# Remove some heanders: Varnish
	unset resp.http.Via;
	unset resp.http.X-Varnish;


  set resp.http.PS-CapabilityList = req.http.PS-CapabilityList;
  if (obj.hits > 0) {
    set resp.http.X-Cache = "HIT";
  } else {
    set resp.http.X-Cache = "MISS";
  }

	return (deliver);
}
 
sub vcl_init {
 	return (ok);
}
 
sub vcl_fini {
 	return (ok);
}
