#!/usr/bin/python

import unittest
import re

from xmpp import *

def normalise_attr(val):
	return val.replace('&', '&amp;').replace('<', '&lt;').replace('"', '&quot;').replace('\t', '&#x9;').replace('\n', '&#xA;').replace('\r', '&#xD;')

def normalise_text(val):
	return val.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\r', '&#xD;')

def c14n(node):
	s = "<" + node.name
	if node.namespace:
		if not node.parent or node.parent.namespace != node.namespace:
			s = s + ' xmlns="%s"' % node.namespace

	sorted_attrs = node.attrs.keys()
	sorted_attrs.sort()
	for key in sorted_attrs:
		val = ustr(node.attrs[key])
		# like XMLescape() but with whitespace and without &gt;
		s = s + ' %s="%s"' % ( key, normalise_attr(val) )
	s = s + ">"
	cnt = 0
	if node.kids:
		for a in node.kids:
			if (len(node.data)-1) >= cnt:
				s = s + normalise_text(node.data[cnt])
			s = s + c14n(a)
			cnt=cnt+1
	if (len(node.data)-1) >= cnt: s = s + normalise_text(node.data[cnt])
	if not node.kids and s[-1:]=='>':
		s=s[:-1]+' />'
	else:
		s = s + "</" + node.name + ">"
	return s

class TestCanonicalization(unittest.TestCase):
	def assertMatch(self, needle, haystack):
		rx = re.compile('.*' + needle + '.*')
		if not rx.search(haystack):
			raise AssertionError(repr('could not find "%s" in "%s")' % (needle, haystack)))

	def test_attribute_order(self):
		n = Node(node='''<field yz='1' ab='2' mn='3'/>''')

		canon = c14n(n)
		self.assertMatch('''ab=.*mn=.*yz=''', canon)

	def test_attribute(self):
		n = Node(node='''<field var='FORM_TYPE' type='hidden'/>''')

		canon = c14n(n)
		self.assertMatch('''var="FORM_TYPE"''', canon)
		self.assertMatch('''type="hidden"''', canon)

		n = Node(node='''<compute expr='value>"0" &amp;&amp; value&lt;"10" ?"valid":"error"'>valid</compute>''')

		canon = c14n(n)
		self.assertMatch('''expr="value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot;''', canon)
		self.assertMatch('''&quot;10&quot; \?&quot;valid&quot;:&quot;error&quot;">''', canon)

	def test_text(self):
		n = Node(node='''<doc>
	<text>First line&#x0d;&#10;Second line</text>
	<value>&#x32;</value>
</doc>''')

		canon = c14n(n)
		self.assertMatch('''<value>2</value>''', canon)
		self.assertMatch('''\t<text>First line&#xD;\nSecond line</text>\n''', canon)

if __name__ == '__main__':
	unittest.main()
