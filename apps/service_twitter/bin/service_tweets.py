#    Copyright (C) 2011-2013 University of Southampton
#    Copyright (C) 2011-2013 Daniel Alexander Smith
#    Copyright (C) 2011-2013 Max Van Kleek
#    Copyright (C) 2011-2013 Nigel R. Shadbolt
#    Copyright (C) 2011-2013 Ramine Tinati
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License, version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse, ast, logging, getpass, sys, urllib2, json, sys, tweepy, datetime
from datetime import datetime
from indxclient import IndxClient
from tweepy.streaming import StreamListener
from tweepy import OAuthHandler
from tweepy import Stream
from tweepy import API

logging.basicConfig(level=logging.INFO)


appid = "twitter_service"

class TwitterService:

    def __init__(self, config):
        config = config.replace("\"","'")
        self.config = ast.literal_eval(config)
        logging.debug("Got config items {0}".format(self.config))
        
        try:
            self.credentials, self.configs, self.twitter_add_info = self.load_parameters(self.config)
            if len(self.credentials)==4 and len(self.configs)>=4:
                print "loading Service Instance"
                self.indx_con = IndxClient(self.credentials['address'], self.credentials['box'], self.credentials['username'], self.credentials['password'], appid)
                self.consumer_key= self.configs['consumer_key']
                self.consumer_secret= self.configs['consumer_secret']
                self.access_token = self.configs['access_token']
                self.access_token_secret = self.configs['access_token_secret']
                self.twitter_username = self.configs['twitter_username']
                self.version = 0
                self.batch = []
                
                #set the auth access control
                self.auth = OAuthHandler(self.consumer_key, self.consumer_secret)
                self.auth.set_access_token(self.access_token, self.access_token_secret)

                #see if other harvesters needed (indx con needed to sumbit data)
                self.load_additional_harvesters(self.twitter_add_info, self.indx_con)

                #now get the tweets
                words_to_search = self.get_search_criteria()
                self.get_tweets(words_to_search)


        except:
            logging.error("could not start TwitterService, check config details - params might be missing")

      

    #load and managed parameters
    def load_parameters(self, config):
        try:
            print "loading Credentials...."
            for k,v in config.iteritems():
                print k,v
            self.credentials = {"address": config['address'], "box": config['box'], "username": config['user'], "password": config['password']} 
            self.configs = {"consumer_key": config['consumer_key'], "consumer_secret": config['consumer_secret'], "access_token": config['access_token'], 
            "access_token_secret": config['access_token_secret'], "twitter_username": config['twitter_username'], "twitter_search_words": config['twitter_search_words']}
            try:
                self.twitter_add_info = {"twitter_status":config['twitter_status'], "twitter_network":config['twitter_network']}
            except:
                self.twitter_add_info = {}

            return (self.credentials, self.configs, self.twitter_add_info)
        except:
            logging.error("COULD NOT START TWITTER APP - NO/INCORRECT CREDENTIALS "+str(sys.exc_info()))
            return False       

    def load_additional_harvesters(self, additional_params, indx_con):
        try:
            #if the user want's to
            is_get_status = additional_params['twitter_status']
            #establish a search connection as welll...
            if "True" in str(is_get_status):
                logging.debug("Adding Twitter Status Harvester")
                self.harvest_private_timeline(indx_con)
        except:
            logging.error("couldnt get status "+str(sys.exc_info()) )

        try:
            is_get_network = additional_params['twitter_network']
            if "True" in str(is_get_network):
                logging.debug("Adding Twitter Network Harvester")
                self.harvest_network(indx_con)
        except:
            logging.error("couldnt get Twitter friends network")



    #this needs to call the database to get the search criteria...    
    def get_search_criteria(self):
        search_terms = []
        username = self.configs['twitter_username']
        words = self.configs['twitter_search_words'].split(",")
        search_terms.append(username)
        for word in words:
            search_terms.append(word)
        return words


    def get_tweets(self, words_to_track):
        l = INDXListener(self)

        stream = Stream(self.auth, l)
        if len(words_to_track) > 0:
            print 'getting tweets...'
            stream.filter(track=words_to_track)
        else:
            stream.sample()


    #datamodel is {timestamp: {friends:[friend_id]}
    def harvest_network(self, indx_con):
        self.api = tweepy.API(self.auth)
        friends_list = self.api.followers_ids(self.twitter_username)
        current_timestamp = str(datetime.now())
        uniq_id = "friends_at_"+current_timestamp
        friends_objs = {"@id":uniq_id, "timestamp":current_timestamp, "friends_list": friends_list}
        version = 0
        #now append the results
        try:
            if len(friends_objs)>0:
                response = indx_con.update(version, friends_objs)
                logging.debug("Inserted Twitter Friendship data".format(response))
        except Exception as e:
            if isinstance(e, urllib2.HTTPError): # handle a version incorrect error, and update the version
                if e.code == 409: # 409 Obsolete
                    response = e.read()
                    json_response = json.loads(response)
                    version = json_response['@version']
                    logging.error('INDX insert error in Twitter Service: '+str(response))
                    try:
                        indx_con.update(version, friends_objs)
                        print "INSERT SUCCESS A SECOND TIME"
                    except:
                        print '-------ERROR: '+str(response)
                else:
                    print '-------ERROR: ',e.read()
            else:
                logging.error("Error updating INDX: {0}".format(e))


    def harvest_private_timeline(self, indx_con):
        return ""




class INDXListener(StreamListener):
    """ A listener handles tweets are the received from the stream.
    This is a basic listener that just prints received tweets to stdout.

    """

    def __init__(self, twitter_serv):
        self.service = twitter_serv        


    def on_data(self, tweet_data):
        """ Assert the tweet into INDX.
        If the version is incorrect, the correct version will be grabbed and the update re-sent.
        
        tweet -- The tweet to assert into the box.
        """

        global appid

        try:
            tweet = json.loads(tweet_data)
            #logging.debug("{0}, {1}".format(type(tweet), tweet))
            if not tweet.get('text'):
                # TODO: log these for provenance?                
                #logging.info("Skipping informational message: '{0}'".format(tweet_data.encode("utf-8")))
                return
            #logging.info("Adding tweet: '{0}'".format(tweet['text'].encode("utf-8")))            
            tweet["@id"] = unicode(tweet['id'])
            tweet["app_object"] = appid
            text = unicode(tweet['text'])
            print text
            self.service.batch.append(tweet)
            if len(self.service.batch) > 25:
                response = self.service.indx_con.update(self.service.version, self.service.batch)
                self.service.version = response['data']['@version'] # update the version
                self.service.batch = []
        except Exception as e:
            if isinstance(e, urllib2.HTTPError): # handle a version incorrect error, and update the version
                if e.code == 409: # 409 Obsolete
                    response = e.read()
                    json_response = json.loads(response)
                    self.service.version = json_response['@version']
                    self.on_data(tweet_data) # try updating again now the version is correct
                else:
                    print '-------ERROR: ',e.read()
            else:
                print "didnt insert tweet"
                logging.error("Error updating INDX: {0}".format(e))
                sys.exit(0)                    
        return True

    def on_error(self, status):
        print "Status Error ",status

# if __name__ == '__main__':



#     credentials, configs = load_parameters()
#     if len(credentials)==4 and len(configs)==4:
#         try:
#             print "Giving Params"
#             service = TwitterService(credentials, configs)
#             words_to_search = service.get_search_criteria()
#             service.get_tweets(words_to_search)
#         except:
#             print "FAILING HERE "+str(sys.exc_info())

