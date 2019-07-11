#!/usr/bin/env python
# -*- coding: utf-8 -*-


class UserDoesntExist(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class GroupDoesntExist(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class AbilityDoesntExist(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ContainerDoesntExist(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
