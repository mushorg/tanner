import pickle


class DorksManager:
    with open('dorks.pickle', 'rb') as fh:
        dorks = pickle.load(fh)
