"""

Python Library for WHM/Cpanel's API2 Email Module

    https://documentation.cpanel.net/display/SDK/Guide+to+cPanel+API+2

Author: Benton Snyder
Website: http://bensnyde.me
Created: 8/15/13
Revised: 5/17/16

"""
import base64
import httplib
import urllib
import json
import logging


class CpanelEmail:
    def __init__(self, whm_base_url, whm_root_user, whm_root_password, cpanel_user):
            """Constructor

                Cpanel Email library public constructor.

            Parameters
                :param whm_base_url: str whm base url (ex. whm.example.com)
                :param whm_root_user: str whm root username
                :param whm_root_password: str whm password
                :param cpanel_user: str cpanel account to run scripts as
            Returns
                None
            """
            self.cpanel_user = cpanel_user
            self.whm_base_url = whm_base_url
            self.whm_headers = {'Authorization':'Basic ' + base64.b64encode(whm_root_user+':'+whm_root_password).decode('ascii')}

    def _whm_api_query(self, script, kwargs):
            """Query WHM API

                Queries specified WHM server's JSON API with specified query string.

            Parameters
                :param script: str API script name
                :param user: str Cpanel username underwhich to call from
                :param kwargs: dict args
            Returns
                :returns: json
            """
            try:
                kwargs.update({
                    'cpanel_jsonapi_func': script,
                    'cpanel_jsonapi_user': self.cpanel_user,
                    'cpanel_jsonapi_module': 'Email',
                    'cpanel_xmlapi_version': 2
                })

                conn = httplib.HTTPSConnection(self.whm_base_url, 2087)
                conn.request('GET', '/json-api/cpanel?%s' % urllib.urlencode(kwargs), headers=self.whm_headers)
                response = conn.getresponse()
                data = json.loads(response.read())
                conn.close()
                return data
            except httplib.HTTPException as ex:
                logging.critical("HTTPException from CpanelEmail API: %s" % ex)
            except ValueError as ex:
                logging.critical("ValueError decoding CpanelEmail API response string: %s" % ex)
            except Exception as ex:
                logging.critical("Unhandled Exception while querying CpanelEmail API: %s" % ex)


    def addpop(self, domain, email, password, quota):
        """Add Email Account

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::addpop

           Parameters
            :param domain: The domain for the new email account
            :param email: The username for the new email account
            :param password: The password for the new email account
            :param quota: A positive integer that defines the disk quota for the email account (0 is unlimited)
        Returns
            :returns: json
        """
        return self._whm_api_query('addpop', {
                'domain': domain,
                'email': email,
                'password': password,
                'quota': quota
        })



    def delpop(self, domain, email):
        """Delete Email Account

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::delpop

        Parameters
            :param domain: The domain for the email account you wish to remove
            :param email: The username for the email address you wish to remove
        Returns
            :returns: json
        """
        return self._whm_api_query('delpop', {
            'domain': domain,
            'email': email
        })


    def editquota(self, domain, email, quota):
        """Edit Quota

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::editquota

        Parameters
            :param domain: The domain for the email account you wish to modify
            :param email: The username for the email address you wish to modify
            :param quota: A positive integer that indicates the desired disk quota value in megabytes (0 is unlimited)
        Returns
            :returns: json
        """
        return self._whm_api_query('editquota', {
            'domain': domain,
            'email': email,
            'quota': quota
        })


    def passwdpop(self, domain, email, password):
        """Change Password

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::passwdpop

        Parameters
            :param domain: The domain for the email address for which you wish to change the password
            :param email: The username for the email address for which you wish to change the password
            :param password: The desired password for the account
        Returns
            :returns: json
        """
        return self._whm_api_query('passwdpop', {
            'domain': domain,
            'email': email,
            'password': password,
        })


    def clearpopcache(self, username):
        """Clear Email Account Cache

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::clearpopcache

        Parameters
            :param username: The username for the email account for which you wish to rebuild the cache file
        Returns
            :returns: json
        """
        return self._whm_api_query('clearpopcache', {
            'username': username
        })


    def listpops(self, regex=None):
        """List Email Accounts

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listpops

        Parameters
            :param regex: The regular expression by which you wish to filter the results
        Returns
            :returns: json
        """
        data = dict()
        if regex:
            data['regex'] = regex

        return self._whm_api_query('listpops', data)


    def listpopssingles(self, regex=None):
        """List Email Accounts w/Logins

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listpopssingles

        Parameters
            :param regex: The regular expression by which you wish to filter the results
        Returns
            :returns: json
        """
        data = dict()
        if regex:
            data['regex'] = regex

        return self._whm_api_query('listpopssingles', data)


    def listpopswithdisk(self, domain=None, nearquotaonly=False, no_validate=False, regex=None):
        """List Email Accounts w/Disk Usage

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listpopswithdisk

        Parameters
            :param domain: The domain for which you wish to view email accounts
            :param nearquotaonly: If you pass 1 to this parameter, you will only view accounts that use 95% or more of their allotted disk space
            :param no_validate: If you pass 1 to this parameter, the function only reads data from your .cpanel/email_accounts.yaml file.
            :param regex: The regular expression by which you wish to filter the results
        Returns
            :returns: json
        """
        data = {
            'nearquotaonly': nearquotaonly,
            'no_validate': no_validate
        }

        if regex:
            data['regex'] = regex
        if domain:
            data['domain'] = domain

        return self._whm_api_query('listpopswithdisk', data)


    def accountname(self, account, display):
        """Get Account Name

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::accountname

        Parameters
            :param account: Specifies the account name or email address. The function will return whichever of these values you do not specify.
            :param display: If present, and you do not specify an account, the function will return the string All Mail On Your Account.
        Returns
            :returns: json
        """
        return self._whm_api_query('accountname', {
            'account': account,
            'display': display
        })


    def getdiskusage(self, domain, user):
        """Get Email Account Disk Usage

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::getdiskusage

        Parameters
            :param domain: The domain that corresponds to the email address for which you wish to view disk usage
            :param user: The username of the email address for which you wish to view disk usage
        Returns
            :returns: json
        """
        return self._whm_api_query('getdiskusage', {
            'domain': domain,
            'user': user
        })


    def listmaildomains(self, skipmain=True):
        """Get Email Domains

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listmaildomains

        Parameters
            :param skipmain: Pass 1 to this variable to skip the main domain
        Returns
            :returns: json
        """
        return self._whm_api_query('listmaildomains', {
            'skipmain': skipmain
        })


    def listlists(self, domain=None, regex=None):
        """Get Mailing Lists

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listlists

        Parameters
            :param domain: The domain for which you wish to view a list of mailing lists
            :param regex: The regular expression by which you wish to filter the results
        Returns
            :returns: json
        """
        data = dict()

        if regex:
            data['regex'] = regex
        if domain:
            data['domain'] = domain

        return self._whm_api_query('listlists', data)


    def setdefaultaddress(self, fwdopt, domain, failmsgs=None, fwdemail=None, pipefwd=None):
        """Set Default Email Address

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::setdefaultaddress

        Parameters
            :param fwdopt: This parameter defines how unroutable mail will be handled.
            :param domain: Specifies the domain to which you wish to apply the rule.
            :param failmsgs: Specifies the failure message that you wish to send if an incoming message bounces.
            :param fwdemail: Specifies the email address to which mail received by the default address is forwarded.
            :param pipefwd: Specifies the program to which messages received by the default address are piped
        Returns
            :returns: json
        """
        data = {
            'fwdopt': fwdopt,
            'domain': domain
        }

        if failmsgs:
            data['failmsgs'] = failmsgs
        if fwdemail:
            data['fwdemail'] = fwdemail
        if pipefwd:
            data['pipefwd'] = pipefwd

        return self._whm_api_query('setdefaultaddress', data)


    def checkmaindiscard(self):
        """Get Discard Settings

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::checkmaindiscard

        Parameters
            None
        Returns
            :returns: json
        """
        return self._whm_api_query('checkmaindiscard', {})


    def listdefaultaddresses(self, domain):
        """Get Default Addresses

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listdefaultaddresses

        Parameters
            :param domain: The domain that corresponds to the default address and information you wish to view
        Returns
            :returns: json
        """
        return self._whm_api_query('listdefaultaddresses', {
            'domain': domain
        })


    def listaliasbackups(self):
        """Get Domains w/Aliases

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listaliasbackups

        Parameters
            None
        Returns
            :returns: json
        """
        return self._whm_api_query('listaliasbackups', {})


    def addforward(self, domain, email, fwdopt, fwdemail=None, fwdsystem=None, failmsgs=None, pipefwd=None):
        """Add Forward

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::addforward

        Parameters
            :param domain: The domain for which you wish to add a forwarder
            :param email: The username of the email address for which you wish to add a forwarder
            :param fwdopt: This parameter defines how unroutable mail will be handled.
            :param fwdemail: The email address to which you wish to forward mail. Use this parameter when fwdopt=fwd.
            :param fwdsystem: The system account to which you wish to forward email. Use this parameter when fwdopt=system.
            :param failmsgs: Use this parameter to define the correct failure message. Use this parameter when fwdopt=fail.
            :param pipefwd: The path to the program to which you wish to pipe email. Use this parameter when fwdopt=pipe.
        Returns
            :returns: json
        """
        data = {
            'email': email,
            'fwdopt': fwdopt,
        }

        if fwdemail:
            data['fwdemail'] = fwdemail
        if fwdsystem:
            data['fwdsystem'] = fwdsystem
        if failmsgs:
            data['failmsgs'] = failmsgs
        if pipefwd:
            data['pipefwd'] = pipefwd

        return self._whm_api_query('addforward', data)


    def listforwards(self, domain=None, regex=None):
        """Get Forwards

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listforwards

        Parameters
            :param domain: The domain name for which you wish to review forwarders
            :param regex: The regular expression by which you wish to filter the results
        Returns
            :returns: json
        """
        data = dict()

        if regex:
            data['regex'] = regex
        if domain:
            data['domain'] = domain

        return self._whm_api_query('listforwards', data)


    def listdomainforwards(self, domain):
        """Get Domain Forwards

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listdomainforwards

        Parameters
            :param domain: The domain that corresponds to the forwarder for which you wish to view the destination
        Returns
            :returns: json
        """
        return self._whm_api_query('listdomainforwards', {
            'domain': domain
        })


    def storefilter(self, account, action, filtername, match, part, val, opt="or", dest=None, oldfiltername=None):
        """Create Email Filter

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::storefilter

        Parameters
            :param account: To configure a user-level filter, enter the email address to which you wish to apply the rule.
            :param action: Specifies the action that the filter takes.
            :param filtername: Specifies the name you wish to give to the new filter
            :param match:  Specifies the new filter match type.
            :param part: The section of the email to which you wish to apply the match parameter.
            :param val: Specifies the value against which you wish to match.
            :param opt: This parameter connects conditionals.
            :param oldfiltername: This function can also be used to rename an existing filter.
            :param dest: Specifies the destination of mail that the filter receives, if one is required.
        Returns
            :returns: json
        """
        data = {
            'account': account,
            'action': action,
            'filtername': filtername,
            'match': match,
            'opt': opt,
            'part': part,
            'val': val
        }

        if dest:
            data['dest'] = dest
        if oldfiltername:
            data['oldfiltername'] = oldfiltername

        return self._whm_api_query('storefilter', data)


    def deletefilter(self, filtername, account=None):
        """Delete Email Filter

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::deletefilter

        Parameters
            :param filtername: Specifies the name of the filter you wish to delete.
            :param account: Specifies an email address or account username that corresponds to the user-level filter you wish to remove.
        Returns
            :returns: json
        """
        return self._whm_api_query('deletefilter', {
            'filtername': filtername,
            'account': account
        })


    def tracefilter(self, msg, account=None):
        """Trace Email Filter

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::tracefilter

        Parameters
            :param msg: The contents of the body of the message you wish to test.
            :param account: This parameter allows you to specify and test old-style cPanel filters in the $home/filters directory.
        Returns
            :returns: json
        """
        return self._whm_api_query('tracefilter', {
            'msg': msg,
            'account': account
        })


    def filterlist(self, account=None):
        """Get Email Filters

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::filterlist

        Parameters
            :param account: Specifies the email address or account username.
        Returns
            :returns: json
        """
        return self._whm_api_query('filterlist', {
            'account': account
        })


    def loadfilter(self, filtername, account=None):
        """Load Email Filter

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::loadfilter

        Parameters
            :param filtername: Specifies the name of the filter you wish to review.
            :param account: Specifies the email address or account username.
        Returns
            :returns: json
        """
        return self._whm_api_query('loadfilter', {
            'account': account,
            'filtername': filtername
        })


    def filtername(self, account=None, filtername=None):
        """Get Suggested Filter Name

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::filtername

        Parameters
            :param account: Specifies the email address associated with the account for which you wish to return a result.
            :param filtername: Specifies a fallback in the case that the function cannot find any relevant filter files.
        Returns
            :returns: json
        """
        return self._whm_api_query('filtername', {
            'account': account,
            'filtername': filtername
        })


    def listfilterbackups(self):
        """Get Domains With Domain Filters

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listfilterbackups

        Parameters
            None
        Returns
            :returns: json
        """
        return self._whm_api_query('listfilterbackups', {})


    def listfilters(self):
        """Get Email Filters

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listfilters

        Parameters
            None
        Returns
            :returns: json
        """
        return self._whm_api_query('listfilters', {})


    def listautoresponders(self, domain=None, regex=None):
        """Get Auto Responders

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::listautoresponders

        Parameters
            :param domain: The domain for which you wish to view auto responders
            :param regex: Regular expressions allow you to filter results based on a set of criteria
        Returns
            :returns: json
        """
        data = dict()

        if regex:
            data['regex'] = regex
        if domain:
            data['domain'] = domain

        return self._whm_api_query('listautoresponders', data)


    def fetchautoresponder(self, email):
        """Get Auto Responder

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::fetchautoresponder

        Parameters
            :param email: The email address that corresponds to the auto responder you wish to review
        Returns
            :returns: json
        """
        return self._whm_api_query('fetchautoresponder', {
            'email': email
        })


    def set_archiving_configuration(self, domain, dtype):
        """Sets the email archiving configuration for the specified domain.

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::set_archiving_configuration

        Parameters
            :param domains: A comma separated list of domains for which you wish to change the configuration
            :param type: An integer, or empty-string, value that indicates the length of time to keep mail archives of the given type.
        Returns
            :returns: json
        """
        return self._whm_api_query('set_archiving_configuration', {
            'domain': domain,
            'type': dtype
        })


    def set_archiving_default_configuration(self, dtype):
        """Set Archiving Configuration

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::set_archiving_default_configuration

        Parameters
            :param type: An integer, or empty-string, value that indicates the length of time to keep mail archives of the given type.
        Returns
            :returns: json
        """
        return self._whm_api_query('set_archiving_default_configuration', {
            'type': dtype
        })


    def get_archiving_configuration(self, domain=None, regex=None):
        """Get Archiving Configuration

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::get_archiving_configuration

        Parameters
            :param domain: The domain name for which you wish to view email archiving configuration information
            :param regex: A case-sensitive regular expression used to filter by domain
        Returns
            :returns: json
        """
        data = dict()

        if regex:
            data['regex'] = regex
        if domain:
            data['domain'] = domain

        return self._whm_api_query('get_archiving_configuration', data)


    def get_archiving_default_configuration(self, domain):
        """Get Default Archiving Configuration

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::get_archiving_default_configuration

        Parameters
            :param domain: The domain for which you wish to view the default configuration
        Returns
            :returns: json
        """
        return self._whm_api_query('get_archiving_default_configuration', {
            'domain': domain
        })


    def get_archiving_types(self):
        """Get Archiving Typse

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::get_archiving_types

        Parameters
            None
        Returns
            :returns: json
        """
        return self._whm_api_query('get_archiving_types', {})


    def getabsbrowsedir(separatedlf, account, adir="mail"):
        """Get Mail Folder Path

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::getabsbrowsedir

        Parameters
            :param account: The email address that corresponds to the directory for which you wish to find the path
            :param dir: The mail folder that you wish to query for its full path
        Returns
            :returns: json
        """
        return self._whm_api_query('getabsbrowsedir', {
            'account': account,
            'dir': adir
        })


    def browseboxes(self, account=None, adir="default", showdotfiles=False):
        """Get Mailboxes

            https://documentation.cpanel.net/display/SDK/cPanel+API+2+Functions+-+Email::browseboxes

        Parameters
            :param account: The name of the email account you wish to review
            :param dir:str = This parameter allows you to specify which mail directories will be displayed.
            :param showdotfiles: A boolean variable that allows you to specify whether you wish to view hidden directories and files
        Returns
            :returns: json
        """
        return self._whm_api_query('browseboxes', {
            'dir': adir,
            'showdotfiles': showdotfiles,
            'account': account
        })
