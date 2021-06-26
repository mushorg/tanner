try:
    import pymongo

    MONGO = True
except ImportError:
    MONGO = False
from bson.objectid import ObjectId
from gridfs import GridFS

from tanner import config


class Reporting:
    def __init__(self):
        if MONGO:
            # Create the connection
            mongo_uri = config.TannerConfig.get("MONGO", "URI")

            connection = pymongo.MongoClient(mongo_uri)

            # Connect to Databases.
            tandb = connection["tanner"]
            tandbfs = connection["voldbfs"]

            # Get Collections
            self.tan_sessions = tandb.sessions
            self.tan_files = GridFS(tandbfs)

            # Indexes
            self.tan_sessions.create_index([("$**", "text")])
        else:
            print("pymongo not found. pip install pymongo")

    def update_session(self, session_id, new_values):
        session_id = ObjectId(session_id)
        self.tan_sessions.update_one({"_id": session_id}, {"$set": new_values})
        return True

    def create_session(self, session_data):
        session_id = self.tan_sessions.insert_one(session_data).inserted_id
        return session_id
