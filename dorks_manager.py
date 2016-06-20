import pickle
import re
import random
import os


class DorksManager:
    with open('dorks.pickle', 'rb') as fh:
        dorks = pickle.load(fh)

    user_dorks = None

    if os.path.exists('user_dorks.pickle'):
        with open('user_dorks.pickle', 'rb') as ud:
            user_dorks = pickle.load(ud)

    def extract_path(self, path):
        extracted = re.match(r'.*\?', path)
        if extracted:
            extracted = extracted.group(0)
            print("extracted %s" % extracted)
            if self.user_dorks and extracted in self.user_dorks:
                return
            with open('user_dorks.pickle', 'ab') as f:
                pickle.dump(extracted, f)
            self.update_user_dorks()

    def update_user_dorks(self):
        with open('user_dorks.pickle', 'rb') as ud:
            self.user_dorks = pickle.load(ud)

    def choose_dorks(self):
        chosen_dorks = []
        subsample_count = random.randint(25, 50)
        chosen_dorks.extend(random.sample(self.dorks, subsample_count))
        try:
            subsample_count = random.randint(25, 50)
            if subsample_count > len(self.user_dorks):
                subsample_count = random.randint(0, len(self.user_dorks))
            chosen_dorks.extend(random.sample(self.user_dorks, subsample_count))
        except TypeError:
            pass

        return chosen_dorks
