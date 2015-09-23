#!/bin/bash

if [ -e /var/rs ]; then
   . /var/rs/etc/scripts/common.sh
   . /var/rs/etc/radicalspam.conf
else
   . /etc/scripts/common.sh
   . /etc/radicalspam.conf
fi

CONFIG=${ADDON_POSTFIX}/etc

postconf -e "myhostname = $MY_HOSTNAME"

# Taille limite en octets (ex : 12582912 = 12Mo) - PREVOIR ENTETES et ENCODAGE
postconf -e "message_size_limit = 0"

# Décommentez et adaptez si l'interface IP de votre MX n'est pas la première IP du serveur
#postconf -e "smtp_bind_address = 127.0.0.2"

postconf -e "alias_maps = hash:$CONFIG/aliases"

postconf -e "alias_database = hash:$CONFIG/aliases"

postconf -e "recipient_canonical_maps = hash:$CONFIG/local-canonical-recipient"

postconf -e "sender_canonical_maps = hash:$CONFIG/local-canonical-sender"

postconf -e "transport_maps = hash:$CONFIG/local-transport, hash:$CONFIG/local-transport-optimize"

postconf -e "relay_domains = \$mydestination, hash:$CONFIG/local-relays"

postconf -e "relay_recipient_maps = hash:$CONFIG/local-directory, hash:$CONFIG/local-exceptions-directory"

postconf -e "smtpd_reject_unlisted_recipient = no"

postconf -e "smtpd_reject_unlisted_sender = no"

postconf -e "smtpd_delay_reject = yes"

postconf -e "smtpd_helo_required = yes"

postconf -e "smtpd_delay_open_until_valid_rcpt = yes"

postconf -e "mynetworks = 127.0.0.0/8"

postconf -e "biff = no"

postconf -e "home_mailbox = .maildir/"

postconf -e "mailbox_size_limit = 0"

postconf -e "smtp_skip_5xx_greeting = no"

postconf -e "smtpd_banner = \$myhostname"

postconf -e "inet_interfaces = 127.0.0.1"

postconf -e "smtpd_client_restrictions = permit_mynetworks, check_client_access hash:$CONFIG/local-whitelist-clients, check_client_access hash:$CONFIG/local-blacklist-clients, reject_rbl_client zen.spamhaus.org"

postconf -e "smtpd_helo_restrictions = check_helo_access hash:$CONFIG/local-exceptions-helo, check_helo_access hash:$CONFIG/local-blacklist-helo, check_helo_access hash:$CONFIG/local-spoofing"

postconf -e "smtpd_sender_restrictions = permit_mynetworks, check_sender_access hash:$CONFIG/local-exceptions-senders, reject_non_fqdn_sender, check_sender_access hash:$CONFIG/local-spoofing, check_sender_access hash:$CONFIG/local-blacklist-senders"

# Permet de répercuter l'activation ou désactivation de Postgrey
ACTIVE_POSTGREY="check_policy_service inet:${POSTGREY_IP}:${POSTGREY_PORT},"
is_enable POSTGREY || ACTIVE_POSTGREY=""

postconf -e "smtpd_recipient_restrictions = check_recipient_access hash:$CONFIG/local-blacklist-recipients, reject_non_fqdn_recipient, reject_unauth_destination, $ACTIVE_POSTGREY reject_unlisted_recipient, check_recipient_access hash:$CONFIG/local-filters"

# Mise à jour des .db :
cd $CONFIG
postmap local-blacklist-clients
postmap local-blacklist-helo
postmap local-blacklist-recipients
postmap local-blacklist-senders
postmap local-canonical-recipient
postmap local-canonical-sender
postmap local-directory
postmap local-filters
postmap local-mynetworks-lan
postmap local-mynetworks-wan
postmap local-relays
postmap local-spoofing
postmap local-transport
postmap local-transport-optimize
postmap local-whitelist-clients
postmap local-exceptions-helo
postmap local-exceptions-senders
postmap local-exceptions-directory
newaliases

exit 0
