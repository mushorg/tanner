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
        max_dorks = 50
        chosen_dorks.extend(random.sample(self.dorks, random.randint(0.5 * max_dorks, max_dorks)))
        try:
            if max_dorks > len(self.user_dorks):
                max_dorks = len(self.user_dorks)
            chosen_dorks.extend(random.sample(self.user_dorks, random.randint(0.5 * max_dorks, max_dorks)))
        except TypeError:
            pass
        finally:
            return chosen_dorks
