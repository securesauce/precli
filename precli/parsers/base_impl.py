# Copyright 2023 Secure Saurce LLC


class BaseImpl:
    def file_extension(self):
        return ""

    def traverse_tree(self, tree):
        cursor = tree.walk()

        reached_root = False
        while reached_root is False:
            yield cursor.node

            if cursor.goto_first_child():
                continue

            if cursor.goto_next_sibling():
                continue

            retracing = True
            while retracing:
                if not cursor.goto_parent():
                    retracing = False
                    reached_root = True

                if cursor.goto_next_sibling():
                    retracing = False
