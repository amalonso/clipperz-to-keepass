"""
The MIT License (MIT)

Copyright (c) 2014 Merlijn van Deen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
"""
from __future__ import unicode_literals
import json, xmltodict, sys
from lxml import etree

def convert(intput_file, output_file):

    if intput_file.endswith(".html"):
        html_str = open(infile, 'rb').read().decode('utf-8')
        root = etree.fromstring(html_str)
        # json string is somewhere in dom tree.
        json_str = root.getchildren()[1].getchildren()[0].getchildren()[2].getchildren()[0].text
    else:
        json_str = open(infile, 'rb').read().decode('utf-8')

    pwds = json.loads(json_str)

    entries = []
    KEEPASS_STRUCTURE = \
    {u'KeePassFile':
        {u'Root':
            {u'Group':
                {u'Name': u'clipperz.is imported passwords',
                u'Entry': entries,
                },
            u'Name': u'(empty group, please remove)'
            }
        }
    }

    for pwd in pwds:
        entries.append(buildentry(pwd))

    open(output_file, 'wb').write(xmltodict.unparse(KEEPASS_STRUCTURE).encode('utf-8'))


def mkentry(data, protected):
    """ data must be a dict {key: value}, protected a list of keys to protect (hide value)
        if UserName, Password, URL, Notes or Title are not given, they are set to ""
    """
    for key in ["UserName", "Password", "URL", "Notes", "Title"]:
        data.setdefault(key, "")
    protected.append("Password")

    return {u'String': [
              {u'Key': field_name, u'Value': {u'#text': filed_value,
                                     u'@ProtectInMemory': 'True' if field_name in protected else 'False'
                                    }
              } for (field_name,filed_value) in data.items()
           ]}

def buildentry(clipperzdict):

    title = clipperzdict['label']

    # clipperzs append label to the end of title, after a special '\ue009' char
    title = title.split('\ue009')[0]
    title = title.rstrip()

    label = {'Title': title}
    protected = []
    fields = clipperzdict['currentVersion']['fields'].values()

    # Don't know what this is. It seems clipperz can conainc direct login to some site.
    if 'data' in clipperzdict and 'directLogins' in clipperzdict['data']:
        for direct_login in clipperzdict['data']['directLogins'].values():
            fields.append({'label': 'URL',
                           'value': direct_login['formData']['attributes']['action'],
                           'hidden': False})

    # now, read all fields of entry and look for some know ones (like UserName, URL and Password) with all possible variations
    for field in fields:
        field_name, filed_value = field['label'], field['value']
        if field_name == "Username or email":
            field_name = "UserName"
        elif field_name == "login":
            field_name = "UserName"
        elif field_name == "Login":
            field_name = "UserName"
        elif field_name == "username":
            field_name = "UserName"
        elif field_name == "Username":
            field_name = "UserName"
        elif field_name == "num adherent":
            field_name = "UserName"
        elif field_name == "num client":
            field_name = "UserName"
        elif field_name == "User Id":
            field_name = "UserName"
        elif field_name == "user Id":
            field_name = "UserName"
        elif field_name == "Web address":
            field_name = "URL"
        elif field_name == "URL":
            field_name = "URL"
        elif field_name == "url":
            field_name = "URL"
        elif field_name == "Site":
            field_name = "URL"
        elif field_name == "Adresse":
            field_name = "URL"
        elif field_name == "adresse":
            field_name = "URL"
        elif field_name == "address":
            field_name = "URL"
        elif field_name == "website":
            field_name = "URL"
        elif field_name == "username":
            field_name = "UserName"
        elif field_name == "password":
            field_name = "Password"
        elif field_name == "Password":
            field_name = "Password"
        elif field_name == "Pass":
            field_name = "Password"
        elif field_name == "pass":
            field_name = "Password"
        else:
            print(f"unknown key: {field_name} for entry {title}")

        # I have no f**** idea of what this is. 
        # It seems initial dev use some pattern like "UserName (1)", "UserName (2)", etc... to list several credentials in single entry
        # Anyway, I never fall in this case.
        if field_name in label:
            i = 0
            while(True):
                i += 1
                nk = field_name + " ({i})"
                if nk not in label:
                    field_name = nk
                    break

        # build dict use to generate keepass entry
        label[field_name] = filed_value
        if field['hidden']:
            protected.append(field_name)
    return mkentry(label,protected)


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage: %s <clipperz.json> <keepass.xml>" % sys.argv[0])

    infile, outfile = sys.argv[1:]

    convert(infile, outfile)