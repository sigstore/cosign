#!/usr/bin/env bash

set -eu

if type realpath >/dev/null 2>&1 ; then
  cd "$(realpath -- $(dirname -- "$0"))"
fi

# posix compliant escape sequence
esc=$'\033'"["
res="${esc}0m"

#
# Defaults
#
DB_NEXT_PATH="_db-next/migrations"
DB_PATH="_db/migrations"
OUTCOME="ERROR"
PROMOTE=()
RUN=()

#
# Print Functions
#
function print_outcome() {
  if [ "${OUTCOME}" == OK ]
  then
    echo -e "${esc}0;32;1m${OUTCOME}${res}"
  else
    echo -e "${esc}0;31;1m${OUTCOME}${res}"
  fi
}

function print_usage_exit() {
  echo "${USAGE}"
  exit 0
}

# newline + bold magenta
function print_heading() {
  echo
  echo -e "${esc}0;34;1m${1}${res}"
}

# bold cyan
function print_moving() {
  local src=${1}
  local dest=${2}
  echo -e "moving:    ${esc}0;36;1m${src}${res}"
  echo -e "to:        ${esc}0;32;1m${dest}${res}"
}

# bold yellow
function print_unlinking() {
  echo -e "unlinking: ${esc}0;33;1m${1}${res}"
}

# bold magenta
function print_linking () {
  local from=${1}
  local to=${2}
  echo -e "linking:   ${esc}0;35;1m${from} ->${res}"
  echo -e "to:        ${esc}0;39;1m${to}${res}"
}

function print_migrations(){
  iter=1
  for file in "${migrations[@]}"
  do
    echo "${iter}) $(basename -- ${file})"
    iter=$(expr "${iter}" + 1)
  done
}

function exit_msg() {
  # complain to STDERR and exit with error
  echo "${*}" >&2
  exit 2
}

#
# Utility Functions
#
function get_promotable_migrations() {
  local migrations=()
  for file in "${DB_NEXT_PATH}"/*.sql; do
    [[ -f "${file}" && ! -L "${file}" ]] || continue
    migrations+=("${file}")
  done
  if [[ "${migrations[@]}" ]]; then
    echo "${migrations[@]}"
  else
    exit_msg "There are no promotable migrations at path: "\"${DB_NEXT_PATH}\"""
  fi
}

function get_demotable_migrations() {
  local migrations=()
  for file in "${DB_NEXT_PATH}"/*.sql; do
    [[ -L "${file}" ]] || continue
    migrations+=("${file}")
  done
  if [[ "${migrations[@]}" ]]; then
    echo "${migrations[@]}"
  else
    exit_msg "There are no demotable migrations at path: "\"${DB_NEXT_PATH}\"""
  fi
}

#
# CLI Parser
#
USAGE="$(cat -- <<-EOM

Usage:
  
  Boulder DB Migrations CLI

  Helper for listing, promoting, and demoting Boulder schema files

  ./$(basename "${0}") [OPTION]...

  -l, --list-next           Lists schema files present in sa/_db-next
  -c, --list-current        Lists schema files promoted from sa/_db-next to sa/_db 
  -p, --promote             Select and promote a schema from sa/_db-next to sa/_db
  -d, --demote              Select and demote a schema from sa/_db to sa/_db-next
  -h, --help                Shows this help message

EOM
)"

while getopts nchpd-: OPT; do
  if [ "$OPT" = - ]; then     # long option: reformulate OPT and OPTARG
    OPT="${OPTARG%%=*}"       # extract long option name
    OPTARG="${OPTARG#$OPT}"   # extract long option argument (may be empty)
    OPTARG="${OPTARG#=}"      # if long option argument, remove assigning `=`
  fi
  case "${OPT}" in
    n | list-next )           RUN+=("list_next") ;;
    c | list-current )        RUN+=("list_current") ;;
    p | promote )             RUN+=("promote") ;;
    d | demote )              RUN+=("demote") ;;
    h | help )                print_usage_exit ;;
    ??* )                     exit_msg "Illegal option --${OPT}" ;;  # bad long option
    ? )                       exit 2 ;;  # bad short option (error reported via getopts)
  esac
done
shift $((OPTIND-1)) # remove parsed opts and args from $@ list

# On EXIT, trap and print outcome
trap "print_outcome" EXIT

STEP="list_next"
if [[ "${RUN[@]}" =~ "${STEP}" ]] ; then
  print_heading "Next Schemas"
  migrations=($(get_promotable_migrations))
  print_migrations "${migrations[@]}"
fi

STEP="list_current"
if [[ "${RUN[@]}" =~ "${STEP}" ]] ; then
  print_heading "Current Schemas"
  migrations=($(get_demotable_migrations))
  print_migrations "${migrations[@]}"
fi

STEP="promote"
if [[ "${RUN[@]}" =~ "${STEP}" ]] ; then
  print_heading "Promote Schema"
  migrations=($(get_promotable_migrations))
  declare -a mig_index=()
  declare -A mig_file=()
  for i in "${!migrations[@]}"; do
    mig_index["$i"]="${migrations[$i]%% *}"
    mig_file["${mig_index[$i]}"]="${migrations[$i]#* }"
  done

  promote=""
  PS3='Which schema would you like to promote? (q to cancel): '
  
  select opt in "${mig_index[@]}"; do
    case "${opt}" in
      "") echo "Invalid option or cancelled, exiting..." ; break ;;
      *)  mig_file_path="${mig_file[$opt]}" ; break ;;
    esac
  done
  if [[ "${mig_file_path}" ]]
  then
    print_heading "Promoting Schema"
    promote_mig_name="$(basename -- "${mig_file_path}")"
    promoted_mig_file_path="${DB_PATH}/${promote_mig_name}"
    symlink_relpath="$(realpath --relative-to=${DB_NEXT_PATH} ${promoted_mig_file_path})"

    print_moving "${mig_file_path}" "${promoted_mig_file_path}"
    mv "${mig_file_path}" "${promoted_mig_file_path}"
    
    print_linking "${mig_file_path}" "${symlink_relpath}"
    ln -s "${symlink_relpath}" "${DB_NEXT_PATH}"
  fi
fi

STEP="demote"
if [[ "${RUN[@]}" =~ "${STEP}" ]] ; then
  print_heading "Demote Schema"
  migrations=($(get_demotable_migrations))
  declare -a mig_index=()
  declare -A mig_file=()
  for i in "${!migrations[@]}"; do
    mig_index["$i"]="${migrations[$i]%% *}"
    mig_file["${mig_index[$i]}"]="${migrations[$i]#* }"
  done

  demote_mig=""
  PS3='Which schema would you like to demote? (q to cancel): '
  
  select opt in "${mig_index[@]}"; do
    case "${opt}" in
      "") echo "Invalid option or cancelled, exiting..." ; break ;;
      *)  mig_link_path="${mig_file[$opt]}" ; break ;;
    esac
  done
  if [[ "${mig_link_path}" ]]
  then
    print_heading "Demoting Schema"
    demote_mig_name="$(basename -- "${mig_link_path}")"
    demote_mig_from="${DB_PATH}/${demote_mig_name}"

    print_unlinking "${mig_link_path}"
    rm "${mig_link_path}"
    print_moving "${demote_mig_from}" "${mig_link_path}"
    mv "${demote_mig_from}" "${mig_link_path}"
  fi
fi

OUTCOME="OK"
