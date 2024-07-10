#!/usr/bin/env python3
#
# By Zoran Bošnjak <zoran.bosnjak@sloveniacontrol.si>
#
# Convert json from new to old format
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import sys
import argparse
import json

def split(obj):
    return (obj['tag'], obj['contents'])

def handle_uap(obj):
    t, cont = split(obj)
    def f(i):
        t, name = split(i)
        if t == 'UapItem':
            return name
        elif t == 'UapItemRFS':
            return 'RFS'
        else:
            return None
    if t == 'Uap':
        return {
            'type': 'uap',
            'items': [f(i) for i in cont],
        }
    elif t == 'Uaps':
        def var(i):
            name, lst = i
            return {
                'name': name,
                'items': [f(i) for i in lst],
            }
        return {
            'type': 'uaps',
            'selector': {
                'name': cont['selector']['item'],
                'rules': cont['selector']['cases'],
            },
            'variations': [var(i) for i in cont['cases']],
        }
    else:
        raise Exception('unexpected', t)

def handle_number(obj):
    t, cont = split(obj)
    if t == 'NumInt':
        return {
            'type': 'Integer',
            'value': cont,
        }
    elif t == 'NumDiv':
        return {
            'type': 'Div',
            'numerator': handle_number(cont['numerator']),
            'denominator': handle_number(cont['denominator']),
        }
    elif t == 'NumPow':
        return {
            'type': 'Pow',
            'base': cont['base'],
            'exponent': cont['exponent'],
        }
    else:
        raise Exception('unexpected', t)

def handle_signedness(obj):
    t, cont = split(obj)
    if t == 'Signed':
        return True
    elif t == 'Unsigned':
        return False
    else:
        raise Exception('unexpected', t)

def handle_constrain(obj):
    t, cont = split(obj)
    if t == 'EqualTo': s = '=='
    elif t == 'NotEqualTo': s = '/='
    elif t == 'GreaterThan': s = '>'
    elif t == 'GreaterThanOrEqualTo': s = '>='
    elif t == 'LessThan': s = '<'
    elif t == 'LessThanOrEqualTo': s = '<='
    else:
        raise Exception('unexpected', t)
    return {
        'type': s,
        'value': handle_number(cont),
    }

def handle_content(obj):
    t, cont = split(obj)
    if t == 'ContentRaw':
        return {
            'type': 'Raw',
        }
    elif t == 'ContentTable':
        return {
            'type': 'Table',
            'values': cont,
        }
    elif t == 'ContentString':
        return {
            'type': 'String',
            'variation': cont['tag'],
        }
    elif t == 'ContentInteger':
        return {
            'type': 'Integer',
            'signed': handle_signedness(cont['signedness']),
            'constraints': [handle_constrain(i) for i in cont['constraints']],
        }
    elif t == 'ContentQuantity':
        return {
            'type': 'Quantity',
            'constraints': [handle_constrain(i) for i in cont['constraints']],
            'lsb': handle_number(cont['lsb']),
            'signed': handle_signedness(cont['signedness']),
            'unit': cont['unit'],
        }
    elif t == 'ContentBds':
        def f(obj):
            t, cont = split(obj)
            if t == 'BdsWithAddress':
                return {
                    'type': 'BdsWithAddress',
                }
            elif t == 'BdsAt':
                return {
                    'type': 'BdsAt',
                    'address': hex(cont)[2:] if cont is not None else None,
                }
            else:
                raise Exception('unexpected', t)
        return {
            'type': 'Bds',
            'variation': f(cont),
        }
    else:
        raise Exception('unexpected', t)

def handle_rule(f, obj):
    t, cont = split(obj)
    if t == 'ContextFree':
        return {
            'type': 'ContextFree',
            'value': f(cont)
        }
    elif t == 'Dependent':
        def g(i):
            a, b = i
            return [
                a,
                f(b),
            ]
        return {
            'type': 'Dependent',
            'items': cont['path'],
            'default': f(cont['default']),
            'cases': [g(i) for i in cont['cases']],
        }
    else:
        raise Exception('unexpected', t)

def handle_item(obj):
    t, cont = split(obj)
    if t == 'Spare':
        return {
            'length': cont,
            'spare': True,
        }
    elif t == 'Item':
        return handle_nonspare(cont)
    else:
        raise Exception('unexpected', t)

def handle_maybe(f, obj):
    if obj is None:
        return None
    return f(obj)

def handle_variation(obj):
    t, cont = split(obj)
    if t == 'Element':
        return {
            'type': t,
            'size': cont['bitSize'],
                'rule': handle_rule(handle_content, cont['rule']),
        }
    elif t == 'Group':
        return {
            'type': t,
            'items': [handle_item(i) for i in cont]
        }
    elif t == 'Extended':
        return {
            'type': t,
            'items': [handle_maybe(handle_item, i) for i in cont],
        }
    elif t == 'Repetitive':
        def f(obj):
            t, cont = split(obj)
            if t == 'RepetitiveRegular':
                return {
                    'type': 'Regular',
                    'size': cont['byteSize']*8,
                }
            elif t == 'RepetitiveFx':
                return {
                    'type': 'Fx',
                }
            else:
                raise Exception('unexpected', t)
        return {
            'type': t,
            'rep': f(cont['type']),
            'variation': handle_variation(cont['variation']),
        }
    elif t == 'Explicit':
        def f(obj):
            if obj is None:
                return None
            t, cont = split(obj)
            if t == 'ReservedExpansion':
                return 'RE'
            elif t == 'SpecialPurpose':
                return 'SP'
            else:
                raise Exception('unexpected', t)
        return {
            'type': t,
            'expl': f(cont),
        }
    elif t == 'Compound':
        return {
            'type': t,
            'fspec': None,
            'items': [handle_maybe(handle_nonspare, i) for i in cont],
        }
    else:
        raise Exception('unexpected', t)

def handle_nonspare(obj):
    doc = obj['documentation']
    return {
        'definition': doc['definition'],
        'description': doc['description'],
        'name': obj['name'],
        'remark': doc['remark'],
        'rule': handle_rule(handle_variation, obj['rule']),
        'spare': False,
        'title': obj['title'],
    }

def has_rfs(obj):
    t, cont = split(obj)
    def check(obj):
        t, cont = split(obj)
        return t == 'UapItemRFS'
    if t == 'Uap':
        return any(check(i) for i in cont)
    elif t == 'Uaps':
        for (uap_name, lst) in cont['cases']:
            if any(check(i) for i in lst):
                return True
        return False
    else:
        raise Exception('unexpected', t)

def handle_asterix(obj):
    t, cont = split(obj)
    if t == 'AsterixBasic':
        catalogue = [handle_nonspare(i) for i in cont['catalogue']]
        if has_rfs(cont['uap']):
            catalogue.append({
                "definition": "Random Field Sequencing\n",
                "description": None,
                "name": "RFS",
                "remark": None,
                "rule": {
                    "type": "ContextFree",
                    "value": {
                        "type": "Rfs"
                    }
                },
                "spare": False,
                "title": "Random Field Sequencing",
            })
        return {
            'catalogue': catalogue,
            'date': cont['date'],
            'edition': cont['edition'],
            'number': cont['category'],
            'preamble': cont['preamble'],
            'title': cont['title'],
            'type': 'Basic',
            'uap': handle_uap(cont['uap']),
        }
    elif t == 'AsterixExpansion':
        return {
            'date': cont['date'],
            'edition': cont['edition'],
            'number': cont['category'],
            'title': cont['title'],
            'type': 'Expansion',
            'variation': {
                'fspec': cont['fspecByteSize']*8,
                'items': [handle_maybe(handle_nonspare, i) for i in cont['items']],
                'type': 'Compound',
            },
        }
    else:
        raise Exception('unexpected', t)

def main():
    parser = argparse.ArgumentParser(description='Convert json from new to old format.')
    parser.add_argument('--in-place', action='store_true')
    parser.add_argument('path')
    args = parser.parse_args()

    with open(args.path, 'r') as f:
        s1 = f.read()

    obj = handle_asterix(json.loads(s1))
    s2 = json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=4)

    if args.in_place:
        with open(args.path, 'w') as f:
            f.write(s2)
    else:
        print(s2)

if __name__ == '__main__':
    main()
