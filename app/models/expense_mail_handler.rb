# Redmine - project management software
# Copyright (C) 2006-2017  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

class ExpenseMailHandler < MailHandler
  include ActionView::Helpers::SanitizeHelper
  include Redmine::I18n

  class UnauthorizedAction < StandardError; end
  class MissingInformation < StandardError; end

  attr_reader :email, :user, :handler_options


  cattr_accessor :ignored_emails_headers
  self.ignored_emails_headers = {
    'Auto-Submitted' => /\Aauto-(replied|generated)/,
    'X-Autoreply' => 'yes'
  }

  private

  MESSAGE_ID_RE = %r{^<?redmine\.([a-z0-9_]+)\-(\d+)\.\d+(\.[a-f0-9]+)?@}
  ISSUE_REPLY_SUBJECT_RE = %r{\[(?:[^\]]*\s+)?#(\d+)\]}
  MESSAGE_REPLY_SUBJECT_RE = %r{\[[^\]]*msg(\d+)\]}

  def dispatch
    headers = [email.in_reply_to, email.references].flatten.compact
    subject = email.subject.to_s
    if headers.detect {|h| h.to_s =~ MESSAGE_ID_RE}
      klass, object_id = $1, $2.to_i
      method_name = "receive_#{klass}_reply"
      if self.class.private_instance_methods.collect(&:to_s).include?(method_name)
        send method_name, object_id
      else
        # ignoring it
      end
    elsif m = subject.match(ISSUE_REPLY_SUBJECT_RE)
      receive_issue_reply(m[1].to_i)
    elsif m = subject.match(MESSAGE_REPLY_SUBJECT_RE)
      receive_message_reply(m[1].to_i)
    else
      dispatch_to_default
    end
  rescue ActiveRecord::RecordInvalid => e
    # TODO: send a email to the user
    logger.error "MailHandler: #{e.message}" if logger
    false
  rescue MissingInformation => e
    logger.error "MailHandler: missing information from #{user}: #{e.message}" if logger
    false
  rescue UnauthorizedAction => e
    logger.error "MailHandler: unauthorized attempt from #{user}" if logger
    false
  end

  def dispatch_to_default
    receive_expense
  end

  # Creates a new issue
  def receive_expense
    project = target_project
    expense = Expense.new(:author => user, :project=> project )
    attributes = expense_attributes_from_keywords(expense)
    expense.safe_attributes = attributes
    expense.safe_attributes = {'custom_field_values' => custom_field_values_from_keywords(expense)}
    expense.description = cleaned_up_text_body
    expense.status_id = 2
    expense.expense_date = Date.today
    expense.save!
    add_attachments(expense)
    logger.info "MailHandler: issue ##{expense.id} created by #{user}" if logger
    expense
  end

  def add_attachments(obj)
    if email.attachments && email.attachments.any?
      email.attachments.each do |attachment|
        next unless accept_attachment?(attachment)
        next unless attachment.body.decoded.size > 0
        obj.attachments << Attachment.create(:container => obj,
                          :file => attachment.body.decoded,
                          :filename => attachment.filename,
                          :author => user,
                          :content_type => attachment.mime_type)
      end
    end
  end

  # Returns false if the +attachment+ of the incoming email should be ignored
  def accept_attachment?(attachment)
    @excluded ||= Setting.mail_handler_excluded_filenames.to_s.split(',').map(&:strip).reject(&:blank?)
    @excluded.each do |pattern|
      if Setting.mail_handler_enable_regex_excluded_filenames?
        regexp = %r{\A#{pattern}\z}i
      else
        regexp = %r{\A#{Regexp.escape(pattern).gsub("\\*", ".*")}\z}i
      end
      if attachment.filename.to_s =~ regexp
        logger.info "MailHandler: ignoring attachment #{attachment.filename} matching #{pattern}"
        return false
      end
    end
    true
  end


  def get_keyword(attr, options={})
    @keywords ||= {}
    if @keywords.has_key?(attr)
      @keywords[attr]
    else
      @keywords[attr] = begin
        override = options.key?(:override) ?
          options[:override] :
          (handler_options[:allow_override] & [attr.to_s.downcase.gsub(/\s+/, '_'), 'all']).present?

        if override && (v = extract_keyword!(cleaned_up_text_body, attr, options[:format]))
          v
        elsif !handler_options[:issue][attr].blank?
          handler_options[:issue][attr]
        end
      end
    end
  end

  # Destructively extracts the value for +attr+ in +text+
  # Returns nil if no matching keyword found
  def extract_keyword!(text, attr, format=nil)
    keys = [attr.to_s.humanize]
    if attr.is_a?(Symbol)
      if user && user.language.present?
        keys << l("field_#{attr}", :default => '', :locale =>  user.language)
      end
      if Setting.default_language.present?
        keys << l("field_#{attr}", :default => '', :locale =>  Setting.default_language)
      end
    end
    keys.reject! {|k| k.blank?}
    keys.collect! {|k| Regexp.escape(k)}
    format ||= '.+'
    keyword = nil
    regexp = /^(#{keys.join('|')})[ \t]*:[ \t]*(#{format})\s*$/i
    if m = text.match(regexp)
      keyword = m[2].strip
      text.sub!(regexp, '')
    end
    keyword
  end

  def get_project_from_receiver_addresses
    local, domain = handler_options[:project_from_subaddress].to_s.split("@")
    return nil unless local && domain
    local = Regexp.escape(local)

    [:to, :cc, :bcc].each do |field|
      header = @email[field]
      next if header.blank? || header.field.blank? || !header.field.respond_to?(:addrs)
      header.field.addrs.each do |addr|
        if addr.domain.to_s.casecmp(domain)==0 && addr.local.to_s =~ /\A#{local}\+([^+]+)\z/
          if project = Project.find_by_identifier($1)
            return project
          end
        end
      end
    end
    nil
  end

  def target_project
    # TODO: other ways to specify project:
    # * parse the email To field
    # * specific project (eg. Setting.mail_handler_target_project)
    target = get_project_from_receiver_addresses
    target ||= Project.find_by_identifier(get_keyword(:project))
    if target.nil?
      # Invalid project keyword, use the project specified as the default one
      default_project = handler_options[:issue][:project]
      if default_project.present?
        target = Project.find_by_identifier(default_project)
      end
    end
    raise MissingInformation.new('Unable to determine target project') if target.nil?
    target
  end

  # Returns a Hash of issue attributes extracted from keywords in the email body
  def expense_attributes_from_keywords(expense)
    attrs = {
      'expense_date' => get_keyword(:expense_date, :format => '\d{4}-\d{2}-\d{2}'),
      'price' => get_keyword(:price)
    }.delete_if {|k, v| v.blank? }

    attrs
  end

  # Returns a Hash of issue custom field values extracted from keywords in the email body
  def custom_field_values_from_keywords(customized)
    customized.custom_field_values.inject({}) do |h, v|
      if keyword = get_keyword(v.custom_field.name)
        h[v.custom_field.id.to_s] = v.custom_field.value_from_keyword(keyword, customized)
      end
      h
    end
  end

  # Returns the text/plain part of the email
  # If not found (eg. HTML-only email), returns the body with tags removed
  def plain_text_body
    return @plain_text_body unless @plain_text_body.nil?

    # check if we have any plain-text parts with content
    @plain_text_body = email_parts_to_text(email.all_parts.select {|p| p.mime_type == 'text/plain'}).presence

    # if not, we try to parse the body from the HTML-parts
    @plain_text_body ||= email_parts_to_text(email.all_parts.select {|p| p.mime_type == 'text/html'}).presence

    # If there is still no body found, and there are no mime-parts defined,
    # we use the whole raw mail body
    @plain_text_body ||= email_parts_to_text([email]).presence if email.all_parts.empty?

    # As a fallback we return an empty plain text body (e.g. if we have only
    # empty text parts but a non-text attachment)
    @plain_text_body ||= ""
  end

  def email_parts_to_text(parts)
    parts.reject! do |part|
      part.attachment?
    end

    parts.map do |p|
      body_charset = Mail::RubyVer.respond_to?(:pick_encoding) ?
                       Mail::RubyVer.pick_encoding(p.charset).to_s : p.charset

      body = Redmine::CodesetUtil.to_utf8(p.body.decoded, body_charset)
      # convert html parts to text
      p.mime_type == 'text/html' ? self.class.html_body_to_text(body) : self.class.plain_text_body_to_text(body)
    end.join("\r\n")
  end

  def cleaned_up_text_body
    @cleaned_up_text_body ||= cleanup_body(plain_text_body)
  end

  def cleaned_up_subject
    subject = email.subject.to_s
    subject.strip[0,255]
  end

  # Converts a HTML email body to text
  def self.html_body_to_text(html)
    Redmine::WikiFormatting.html_parser.to_text(html)
  end

  # Converts a plain/text email body to text
  def self.plain_text_body_to_text(text)
    # Removes leading spaces that would cause the line to be rendered as
    # preformatted text with textile
    text.gsub(/^ +(?![*#])/, '')
  end

  def self.assign_string_attribute_with_limit(object, attribute, value, limit=nil)
    limit ||= object.class.columns_hash[attribute.to_s].limit || 255
    value = value.to_s.slice(0, limit)
    object.send("#{attribute}=", value)
  end

  # Returns a User from an email address and a full name
  def self.new_user_from_attributes(email_address, fullname=nil)
    user = User.new

    # Truncating the email address would result in an invalid format
    user.mail = email_address
    assign_string_attribute_with_limit(user, 'login', email_address, User::LOGIN_LENGTH_LIMIT)

    names = fullname.blank? ? email_address.gsub(/@.*$/, '').split('.') : fullname.split
    assign_string_attribute_with_limit(user, 'firstname', names.shift, 30)
    assign_string_attribute_with_limit(user, 'lastname', names.join(' '), 30)
    user.lastname = '-' if user.lastname.blank?
    user.language = Setting.default_language
    user.generate_password = true
    user.mail_notification = 'only_my_events'

    unless user.valid?
      user.login = "user#{Redmine::Utils.random_hex(6)}" unless user.errors[:login].blank?
      user.firstname = "-" unless user.errors[:firstname].blank?
      (puts user.errors[:lastname];user.lastname  = "-") unless user.errors[:lastname].blank?
    end

    user
  end

  # Creates a User for the +email+ sender
  # Returns the user or nil if it could not be created
  def create_user_from_email
    from = email.header['from'].to_s
    addr, name = from, nil
    if m = from.match(/^"?(.+?)"?\s+<(.+@.+)>$/)
      addr, name = m[2], m[1]
    end
    if addr.present?
      user = self.class.new_user_from_attributes(addr, name)
      if handler_options[:no_notification]
        user.mail_notification = 'none'
      end
      if user.save
        user
      else
        logger.error "MailHandler: failed to create User: #{user.errors.full_messages}" if logger
        nil
      end
    else
      logger.error "MailHandler: failed to create User: no FROM address found" if logger
      nil
    end
  end

  # Adds the newly created user to default group
  def add_user_to_group(default_group)
    if default_group.present?
      default_group.split(',').each do |group_name|
        if group = Group.named(group_name).first
          group.users << @user
        elsif logger
          logger.warn "MailHandler: could not add user to [#{group_name}], group not found"
        end
      end
    end
  end

  # Removes the email body of text after the truncation configurations.
  def cleanup_body(body)
    delimiters = Setting.mail_handler_body_delimiters.to_s.split(/[\r\n]+/).reject(&:blank?)

    if Setting.mail_handler_enable_regex_delimiters?
      begin
        delimiters = delimiters.map {|s| Regexp.new(s)}
      rescue RegexpError => e
        logger.error "MailHandler: invalid regexp delimiter found in mail_handler_body_delimiters setting (#{e.message})" if logger
      end
    end

    unless delimiters.empty?
      regex = Regexp.new("^[> ]*(#{ Regexp.union(delimiters) })[[:blank:]]*[\r\n].*", Regexp::MULTILINE)
      body = body.gsub(regex, '')
    end
    body.strip
  end

  def find_assignee_from_keyword(keyword, issue)
    Principal.detect_by_keyword(issue.assignable_users, keyword)
  end
end
