#!/usr/bin/env python3

import sys
import re

docStartRe = re.compile('^/\*$')
docEndRe = re.compile('^ \*/$')
docTextRe = re.compile('^ \* ?(.*)$')
docSectionRe = re.compile('^/\*{3,} (.*) \*{3,}/$')

structDefRe = re.compile('^struct ([a-zA-Z0-9_]+)$')
enumDefRe = re.compile('^enum ([a-zA-Z0-9_]+)$')
funcDefRe = re.compile('([a-zA-Z0-9_]+ )+(\*)*([a-zA-Z0-9_]+)\(.*\);?')
fptrTypedefRe = re.compile('^typedef\s+.*\(([a-zA-Z0-9_]+_t)\)\(.*\);$')
typeTypedefRe = re.compile('^typedef\s+.*\s+([a-zA-Z0-9_]+_t);$')
defineRe = re.compile('^#define\s+([a-zA-Z0-9_]+)');

def process_doc_block(docText, lines):
    if not lines:
        return
    first = lines[0]

    funcMatch = funcDefRe.match(first)
    if funcMatch:
        return ('func', funcMatch.group(3), docText, lines)
    structMatch = structDefRe.match(first)
    if structMatch:
        return ('struct', structMatch.group(1), docText, lines)
    enumMatch = enumDefRe.match(first)
    if enumMatch:
        return ('enum', enumMatch.group(1), docText, lines)
    fptrTypedefMatch = fptrTypedefRe.match(first)
    if fptrTypedefMatch:
        return ('typedef', fptrTypedefMatch.group(1), docText, lines)
    typeTypedefMatch = typeTypedefRe.match(first)
    if typeTypedefMatch:
        return ('typedef', typeTypedefMatch.group(1), docText, lines)
    defineReMatch = defineRe.match(first)
    if defineReMatch:
        return ('macro', defineReMatch.group(1), docText, lines)

def escape(s):
    return s.replace('_', r'\_')

def tt(s):
    return r'{\tt ' + escape(s) + '}'

def tt2(s):
    return escape(re.sub(r'`([^`]*)`', r'\\texttt{\1}', s))

objs = []
filename = sys.argv[1]
with open(filename, 'r', encoding="UTF8") as input_file:
    objs.append(('file', filename, None, None))
    for block in input_file.read().split("\n\n"):
        insideDoc = False
        docTextLines = []
        lines = block.split("\n")
        for idx, line in enumerate(lines):
            sectionMatch = docSectionRe.match(line)
            if sectionMatch:
                assert not insideDoc
                objs.append(('section', sectionMatch.group(1), '', []))
            elif docStartRe.match(line):
                assert not insideDoc
                insideDoc = True
            elif docEndRe.match(line):
                assert insideDoc
                insideDoc = False
                docText = "\n".join(docTextLines)
                if len(lines) > idx + 1:
                    obj = process_doc_block(docText, lines[idx + 1:])
                    if obj:
                        objs.append(obj)
                else:
                    objs.append(('text', None, docText, []))
            elif insideDoc:
                match = docTextRe.match(line)
                assert match
                docTextLines.append(match.group(1))

for obj in objs:
    kind, name, docText, src = obj
    if docText:
        docText = re.sub(r'TODO.*$', '', docText)
    if kind == 'section':
        print(r'\subsection{{{}}}'.format(name))
    elif kind == 'file':
        print(r'\section' + tt(name))
        print(r'\label{{api:{}}}'.format(name))
    elif kind == 'text':
        print(tt2(docText))
        print()
    else:
        print(r'\subsubsection{{{} {}}}'.format(kind.title(), escape(name)))
        print()
        print(tt2(docText))
        print(r'\begin{Verbatim}[obeytabs=true,fontsize=\scriptsize]')
        print(src[0] if kind == 'func' else "\n".join(src))
        print(r'\end{Verbatim}')
        print()
