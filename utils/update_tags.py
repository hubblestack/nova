import sys
import logging
try:
    import xlrd
except ImportError:
    print '\n\npackage "xlrd" is required. Try:\n# pip install xlrd\n\n'
    exit()

def main():
    help_message = \
        '''
Usage:
    # python update_tags.py <optional_tag> <.yaml> <.xls>
Optional tags:
    -t : templates cis standards that aren't included in yaml into the updated version.

This script has does four things:
1. Updates tags in yaml profile to match the cis standards, saved at <.yaml>_updated.yaml.
    It updates the tags based on the matching the tag description to cis standard title.
2. Finds format errors in yaml profile.
3. Finds outdated audits in the yaml profile.
4. Finds audits in the cis standards that aren't found in the yaml profile.
It also saves a log of the results of each run at <.yaml>_updated.log\n
        '''
    args = sys.argv
    if len(args) != 3 and len(args) != 4:
        print help_message
        exit()

    try:
        cis_xls = args[3]
        yaml_profile = args[2]
        optional = args[1]
    except IndexError:
        cis_xls = sys.argv[2]
        yaml_profile = sys.argv[1]
        optional = None

    if not cis_xls.endswith('.xls') or not yaml_profile.endswith('.yaml'):
        print help_message
        exit()
    if optional not in [None, '-t']:
        print help_message
        exit()

    report = create_report(yaml_profile, cis_xls)
    _update_yaml(report, yaml_profile, optional)
    _log_report(report, yaml_profile)

def create_report(yaml_profile, cis_xls):
    '''
    Return a report on what needs to be fixed in the yaml file
        based on the cis_standards.
    '''
    if 'rhelw' in yaml_profile:
        sheet_index = 3
    else:
        sheet_index=1

    cis_standards = _get_cis(cis_xls, sheet_index)
    yaml_lines = open(yaml_profile).readlines()

    ret = {'format_errors': [], 'updated_uids': [],
           'missing_standards': [], 'outdated_uids': []}
    checked_standards = set()

    for i, line in enumerate(yaml_lines):
        if 'data:' in line:
            if i == 0:
                ret['format_errors'].append(('None', i))
                continue
            uid = yaml_lines[i-1].strip().strip(':')
            desc, tag = _get_data(yaml_lines, i)
            if not desc or not tag:
                ret['format_errors'].append((uid, i))
                continue
            if desc not in cis_standards:
                ret['outdated_uids'].append((uid, i))
                continue
            cis_tag = cis_standards[desc]
            checked_standards.add(desc)
            if '_' in tag:
                _, addon = tag.split('_')
                cis_tag += '_' + addon
            if cis_tag != tag:
                ret['updated_uids'].append((uid, i, tag, cis_tag))
                continue
    leftover_standards = cis_standards.keys()
    for desc in checked_standards:
        leftover_standards.remove(desc)
    for desc in leftover_standards:
        _tag = cis_standards[desc]
        ret['missing_standards'].append((desc, _tag))
    return ret


def _get_data(yaml_lines, data_index):
    '''
    Return the tag and description for a given data layer,
        or (None, None) if there is a format error.
    '''
    data_indent = _get_indent(yaml_lines[data_index])
    description = None
    tag = None
    for i, line in enumerate(yaml_lines[data_index+1:]):
        line_indent = _get_indent(line)
        if line_indent  < data_indent:
            if tag and description:
                return (description.lower(), tag)
            else:
                return (None, None)
        if 'description:' in line:
            if description is not None:
                return (None, None)
            else:
                description = line.strip().lstrip('description:').strip()
        elif 'CIS-' in line:
            _, _tag = line.split('CIS-')
            _tag = 'CIS-' + _tag.strip()
            if tag is not None:
                if tag != _tag:
                    return (None, None)
            else:
                tag = _tag
    # End of file
    else:
        if tag and description:
            return (description.lower(), tag)
        return (None, None)


def _log_report(report, yaml_filename):
    yaml_filename = yaml_filename.rstrip('.yaml') + '_updated.log'
    logging.basicConfig(
            level=logging.INFO,
            filename=yaml_filename,
            filemode='w',
            format='%(name)s - %(message)s'
            )
    format_log = logging.getLogger('format_error')
    outdated_log = logging.getLogger('outdated_yaml')
    missing_log = logging.getLogger('missing_audits')
    updated_log = logging.getLogger('updated_tags')
    linebreak = logging.getLogger(' ')

    err_message = 'uid: %s, line: %s'
    for uid, line in report['format_errors']:
        format_log.info(err_message, uid, line)
    linebreak.info('')
    for uid, line in report['outdated_uids']:
        outdated_log.info(err_message, uid, line)
    linebreak.info('')

    outdated_message = 'tag: %s, description: %s'
    for desc, tag in report['missing_standards']:
        missing_log.info(outdated_message, tag, desc)
    linebreak.info('')

    updated_message = '(%s --> %s), uid: %s, line %s'
    for uid, line, old_tag, new_tag in report['updated_uids']:
        updated_log.info(updated_message, old_tag, new_tag, uid, line)
    if report['updated_uids']:
        linebreak.info('')
        linebreak.info('Saved updates at %s', yaml_filename.replace('.log', '.yaml'))
    logfile = open(yaml_filename)
    print logfile.read()
    print 'Saved logfile at %s' % yaml_filename
    logfile.close()

def _get_indent(line):
    '''Return length of indent of line'''
    return len(line) - len(line.lstrip(' '))


def _update_yaml(report, yaml_filename, optional):
    '''Write a new file with the updates as described by updated_uids'''
    updates = report['updated_uids']
    yaml_lines = open(yaml_filename).readlines()
    _updates = []
    for uid, data_index, old_tag, new_tag in updates:
        _updates.extend(_update_data(yaml_lines, data_index, new_tag=new_tag))
    for i, updated_line in _updates:
        yaml_lines[i] = updated_line
    yaml_filename = yaml_filename.rstrip('.yaml') + '_updated.yaml'
    new_yaml = open(yaml_filename, 'w')
    for line in yaml_lines:
        new_yaml.write(line)
    if optional == '-t':
        template = \
'''
changeme:
  data:
    %s
      - changeme:
        tag: %s
      - changeme: %s
    description: %s
'''
        osfinger = _get_osfinger(yaml_lines)
        for tag, desc in report['missing_standards']:
            new_yaml.write(template % (osfinger, tag, tag, desc))
    new_yaml.close()

def _get_osfinger(yaml_lines):
    for i, line in enumerate(yaml_lines):
        if '  data:' in line:
            os_finger = yaml_lines[i+1].strip()
            return os_finger
    return 'changeme:'


def _update_data(yaml_lines, data_index, new_tag=None):
    '''Return list of lines to update per data layer.'''
    updates = []
    data_indent = _get_indent(yaml_lines[data_index])
    for i, line in enumerate(yaml_lines[data_index:]):
        line_indent = _get_indent(line)
        if line_indent  < data_indent:
            break
        if 'CIS-' in line:
            if not new_tag:
                continue
            updated_line, _ = line.split('CIS-')
            updated_line += new_tag + '\n'
            updates.append((i + data_index, updated_line))
    return updates


def _get_cis(xls_filename, sheet_index=1):
    '''Return dictionary of cis title's and their corresponding cis tag'''
    tag_col = 1
    title_col = 2
    score_col = 4

    workbook = xlrd.open_workbook(xls_filename)
    worksheet = workbook.sheet_by_index(sheet_index)

    ret = {}

    for row_num in range(1,worksheet.nrows):
        scoring_status = worksheet.cell(row_num, score_col).value
        if scoring_status != 'scored':
            continue

        title = str(worksheet.cell(row_num, title_col).value).lower()
        rec_num = worksheet.cell(row_num, tag_col).value
        if isinstance(rec_num, float):
            rec_num = str(rec_num) + '0'
        rec_num = 'CIS-' + str(rec_num)
        ret[title] = rec_num
    return ret

if __name__ == '__main__':
    main()
