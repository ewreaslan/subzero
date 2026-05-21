"""
Subdomain takeover fingerprint database.

Each entry defines:
  cname_patterns  : substrings to match against CNAME target
  http_fingerprints: strings that appear in the HTTP body when the service is unclaimed
  status_codes    : HTTP status codes that indicate an unclaimed service
  nxdomain        : True if the service goes NXDOMAIN when not configured
  confidence_body : points awarded when an HTTP body fingerprint matches
  confidence_cname: points awarded when a CNAME pattern matches
  takeover_info   : human-readable notes on how to take over
  references      : public write-ups / documentation
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Fingerprint:
    name: str
    cname_patterns: list[str]
    http_fingerprints: list[str]
    status_codes: list[int]
    nxdomain: bool
    confidence_body: int
    confidence_cname: int
    takeover_info: str
    references: list[str] = field(default_factory=list)
    service_check: Optional[str] = None  # identifier for service-specific validator


FINGERPRINTS: list[Fingerprint] = [
    Fingerprint(
        name="GitHub Pages",
        cname_patterns=["github.io"],
        http_fingerprints=[
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
            "githubapp.com",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Create a GitHub repo matching the CNAME and enable Pages.",
        references=["https://docs.github.com/en/pages"],
        service_check="github_pages",
    ),
    Fingerprint(
        name="Amazon S3",
        cname_patterns=["s3.amazonaws.com", "s3-website"],
        http_fingerprints=[
            "NoSuchBucket",
            "The specified bucket does not exist",
            "NoSuchWebsiteConfiguration",
        ],
        status_codes=[404, 403],
        nxdomain=False,
        confidence_body=45,
        confidence_cname=35,
        takeover_info="Register the S3 bucket with the exact subdomain name.",
        references=["https://hackerone.com/reports/186766"],
        service_check="s3",
    ),
    Fingerprint(
        name="Amazon CloudFront",
        cname_patterns=["cloudfront.net"],
        http_fingerprints=[
            "The request could not be satisfied",
            "ERROR: The request could not be satisfied",
            "Bad request",
            "d111111abcdef8.cloudfront.net",
        ],
        status_codes=[403],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Create a CloudFront distribution pointing to the origin.",
        references=[],
    ),
    Fingerprint(
        name="Heroku",
        cname_patterns=["herokudns.com", "herokussl.com", "herokuapp.com"],
        http_fingerprints=[
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
            "There's nothing here, yet.",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Create a Heroku app with the matching name.",
        references=["https://blog.heroku.com/security-reporting"],
        service_check="heroku",
    ),
    Fingerprint(
        name="Fastly",
        cname_patterns=["fastly.net"],
        http_fingerprints=[
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
            "fastly error",
        ],
        status_codes=[500, 503],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Add the domain to a Fastly service.",
        references=[],
    ),
    Fingerprint(
        name="Shopify",
        cname_patterns=["myshopify.com", "shops.myshopify.com"],
        http_fingerprints=[
            "Sorry, this shop is currently unavailable.",
            "Only one step left",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Register a Shopify store with the matching subdomain.",
        references=["https://hackerone.com/reports/shotofcode"],
    ),
    Fingerprint(
        name="Zendesk",
        cname_patterns=["zendesk.com"],
        http_fingerprints=[
            "Help Center Closed",
            "Oops, this help center no longer exists",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Create a Zendesk account using the matching subdomain.",
        references=[],
    ),
    Fingerprint(
        name="Tumblr",
        cname_patterns=["tumblr.com"],
        http_fingerprints=[
            "Whatever you were looking for doesn't currently exist at this address.",
            "There's nothing here.",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Create a Tumblr blog and set the custom domain.",
        references=[],
    ),
    Fingerprint(
        name="Ghost",
        cname_patterns=["ghost.io"],
        http_fingerprints=[
            "The thing you were looking for is no longer here",
            "Failed to load resource",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Register a Ghost(Pro) blog with the matching domain.",
        references=[],
    ),
    Fingerprint(
        name="Pantheon",
        cname_patterns=["pantheonsite.io", "pantheon.io"],
        http_fingerprints=[
            "The gods are wise, but do not know of the site which you seek.",
            "pantheon-upstream",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Create a Pantheon site and add the custom domain.",
        references=[],
    ),
    Fingerprint(
        name="Unbounce",
        cname_patterns=["unbouncepages.com"],
        http_fingerprints=[
            "The requested URL was not found on this server.",
            "punycode",
        ],
        status_codes=[404, 301],
        nxdomain=False,
        confidence_body=30,
        confidence_cname=30,
        takeover_info="Register an Unbounce account and claim the domain.",
        references=[],
    ),
    Fingerprint(
        name="HubSpot",
        cname_patterns=["hubspot.com", "hubspotpagebuilder.com", "hs-sites.com"],
        http_fingerprints=[
            "Domain not found",
            "This page isn't available",
            "does not exist in our system",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Connect the domain to a HubSpot account.",
        references=[],
    ),
    Fingerprint(
        name="Webflow",
        cname_patterns=["webflow.io", "proxy.webflow.com"],
        http_fingerprints=[
            "The page you are looking for doesn't exist or has been moved.",
            "Oops! That page can't be found.",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Add the domain to a Webflow project.",
        references=[],
    ),
    Fingerprint(
        name="Netlify",
        cname_patterns=["netlify.app", "netlify.com"],
        http_fingerprints=[
            "Not Found - Request ID",
            "netlify-domain-not-found",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Deploy a Netlify site and add the custom domain.",
        references=[],
    ),
    Fingerprint(
        name="Vercel",
        cname_patterns=["vercel.app", "now.sh"],
        http_fingerprints=[
            "The deployment you are looking for",
            "This Deployment has been suspended",
            "DEPLOYMENT_NOT_FOUND",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Deploy a Vercel project and add the custom domain.",
        references=[],
    ),
    Fingerprint(
        name="Surge.sh",
        cname_patterns=["surge.sh"],
        http_fingerprints=[
            "project not found",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=35,
        takeover_info="Run `surge` CLI and claim the subdomain as a project.",
        references=["https://surge.sh/help/adding-a-custom-domain"],
    ),
    Fingerprint(
        name="Bitbucket Pages",
        cname_patterns=["bitbucket.io"],
        http_fingerprints=[
            "Repository not found",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Create a Bitbucket repository matching the subdomain.",
        references=[],
    ),
    Fingerprint(
        name="Azure (App Service / CDN)",
        cname_patterns=[
            "azurewebsites.net",
            "cloudapp.net",
            "cloudapp.azure.com",
            "trafficmanager.net",
            "blob.core.windows.net",
            "azure-api.net",
        ],
        http_fingerprints=[
            "404 Web Site not found",
            "Microsoft Azure App Service",
            "App Service - Placeholder",
            "This web app has been stopped",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Register the App Service / Storage account with exact name.",
        references=["https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover"],
    ),
    Fingerprint(
        name="Google Cloud (GCS / AppEngine)",
        cname_patterns=[
            "storage.googleapis.com",
            "appspot.com",
            "c.storage.googleapis.com",
        ],
        http_fingerprints=[
            "NoSuchBucket",
            "The specified bucket does not exist",
            "404. That's an error.",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Create a GCS bucket or App Engine app with the matching name.",
        references=[],
    ),
    Fingerprint(
        name="Intercom",
        cname_patterns=["intercom.help", "custom.intercom.help"],
        http_fingerprints=[
            "This page is reserved for artistic dogs.",
            "Uh oh. That page doesn't exist.",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Create an Intercom Help Center and assign the domain.",
        references=[],
    ),
    Fingerprint(
        name="Wix",
        cname_patterns=["wix.com", "parastorage.com"],
        http_fingerprints=[
            "Looks Like This Domain Isn't Connected To A Website Yet!",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Create a Wix site and connect the domain.",
        references=[],
    ),
    Fingerprint(
        name="Squarespace",
        cname_patterns=["squarespace.com", "squarespace-cdn.com"],
        http_fingerprints=[
            "No Such Account",
            "You need to assign a website to this domain",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Create a Squarespace site and assign the custom domain.",
        references=[],
    ),
    Fingerprint(
        name="Acquia",
        cname_patterns=["acquia-sites.com"],
        http_fingerprints=[
            "Web Site Not Found",
            "The site you are looking for could not be found.",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Create an Acquia site and claim the domain.",
        references=[],
    ),
    Fingerprint(
        name="AWS Elastic Beanstalk",
        cname_patterns=["elasticbeanstalk.com"],
        http_fingerprints=[
            "NXDOMAIN",
        ],
        status_codes=[],
        nxdomain=True,
        confidence_body=0,
        confidence_cname=35,
        takeover_info="Create a new Elastic Beanstalk environment and bind the subdomain.",
        references=[
            "https://github.com/EdOverflow/can-i-take-over-xyz",
            "https://docs.aws.amazon.com/elasticbeanstalk/",
        ],
    ),
    Fingerprint(
        name="Discourse",
        cname_patterns=["trydiscourse.com"],
        http_fingerprints=[
            "NXDOMAIN",
        ],
        status_codes=[],
        nxdomain=True,
        confidence_body=0,
        confidence_cname=35,
        takeover_info="Create a Discourse instance and claim the custom hostname.",
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
    ),
    Fingerprint(
        name="Gemfury",
        cname_patterns=["furyns.com"],
        http_fingerprints=[
            "404: This page could not be found.",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=35,
        takeover_info="Create a Gemfury account and re-assign the custom domain.",
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
    ),
    Fingerprint(
        name="Help Scout Docs",
        cname_patterns=["helpscoutdocs.com"],
        http_fingerprints=[
            "No settings were found for this company:",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Create a Help Scout Docs site and bind the orphaned domain.",
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
    ),
    Fingerprint(
        name="JetBrains YouTrack Cloud",
        cname_patterns=["youtrack.cloud"],
        http_fingerprints=[
            "is not a registered InCloud YouTrack",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Register the YouTrack Cloud instance and add the custom domain.",
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
    ),
    Fingerprint(
        name="Ngrok",
        cname_patterns=["ngrok.io"],
        http_fingerprints=[
            "Tunnel",
            "not found",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=30,
        takeover_info="Create an ngrok tunnel endpoint and claim the subdomain.",
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
    ),
    Fingerprint(
        name="SurveySparrow",
        cname_patterns=["surveysparrow.com"],
        http_fingerprints=[
            "Account not found.",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=30,
        takeover_info="Create a SurveySparrow account and attach the custom domain.",
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
    ),
    Fingerprint(
        name="Uberflip",
        cname_patterns=["read.uberflip.com"],
        http_fingerprints=[
            "The URL you've accessed does not provide a hub.",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=40,
        confidence_cname=35,
        takeover_info="Create an Uberflip hub and assign the dangling domain.",
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
    ),
    Fingerprint(
        name="UptimeRobot",
        cname_patterns=["stats.uptimerobot.com"],
        http_fingerprints=[
            "page not found",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=35,
        takeover_info="Create a public status page and claim the subdomain.",
        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
    ),
    Fingerprint(
        name="Cargo",
        cname_patterns=["cargocollective.com"],
        http_fingerprints=[
            "404 Not Found",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=25,
        confidence_cname=35,
        takeover_info="Register a Cargo account and claim the subdomain.",
        references=[],
    ),
    Fingerprint(
        name="ReadMe.io",
        cname_patterns=["readme.io", "readmessl.com"],
        http_fingerprints=[
            "Project doesnt exist... yet!",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=45,
        confidence_cname=30,
        takeover_info="Create a ReadMe project and assign the custom domain.",
        references=[],
    ),
    Fingerprint(
        name="Strikingly",
        cname_patterns=["s.strikinglydns.com"],
        http_fingerprints=[
            "page not found",
            "is available for purchase",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=30,
        confidence_cname=35,
        takeover_info="Register a Strikingly site and claim the domain.",
        references=[],
    ),
    Fingerprint(
        name="Tilda",
        cname_patterns=["tilda.ws"],
        http_fingerprints=[
            "Please renew your subscription",
            "Domain is not connected",
        ],
        status_codes=[404],
        nxdomain=False,
        confidence_body=35,
        confidence_cname=35,
        takeover_info="Create a Tilda project and connect the domain.",
        references=[],
    ),
]


def match_cname(cname: str) -> Optional[Fingerprint]:
    """Return first fingerprint whose cname_patterns appear in the given CNAME."""
    cname_lower = cname.lower()
    for fp in FINGERPRINTS:
        for pattern in fp.cname_patterns:
            if pattern in cname_lower:
                return fp
    return None


def match_body(body: str) -> list[tuple[Fingerprint, str]]:
    """Return all fingerprints that match substrings in the HTTP body."""
    matches: list[tuple[Fingerprint, str]] = []
    body_lower = body.lower()
    for fp in FINGERPRINTS:
        for phrase in fp.http_fingerprints:
            if phrase.lower() in body_lower:
                matches.append((fp, phrase))
                break
    return matches
