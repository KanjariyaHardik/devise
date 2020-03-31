# frozen_string_literal: true

require 'devise/strategies/authenticatable'

module Devise
  module Strategies
    # Default strategy for signing in a user, based on their email and password in the database.
    class DatabaseAuthenticatable < Authenticatable
      def authenticate!
        resource  = password.present? && mapping.to.find_for_database_authentication(authentication_hash)
        hashed = false

        if validate(resource){ hashed = true; resource.valid_password?(password) } && custom_validate(resource)

          remember_me(resource)
          resource.after_database_authentication
          success!(resource)
        end

        # In paranoid mode, hash the password even when a resource doesn't exist for the given authentication key.
        # This is necessary to prevent enumeration attacks - e.g. the request is faster when a resource doesn't
        # exist in the database if the password hashing algorithm is not called.
        mapping.to.new.password = password if !hashed && Devise.paranoid
        unless resource
          Devise.paranoid ? fail(:invalid) : fail(:not_found_in_database)
        end
      end

      def custom_validate(resource)
        if is_admin_user?(resource)
          has_access = check_subdomain_access(resource)
          # binding.pry
          has_access
        else
          true
        end
      end

      def check_subdomain_access(resource)
        domain = DomainList.where(domain: request.subdomain).first
        campaign = nil

        if domain.present?
          organization = Organization.where(id: domain.organization_id).first
          campaign = Campaign.where(id: domain.campaign_id).first
        else
          organization = Organization.where(sub_domain: request.subdomain).first
        end

        if organization.present?
          if campaign.present?
            camp_user = CampaignUser.where.not(role: 0).where(campaign_id: campaign.id, user_id: resource.id).first
            if camp_user
              return true
            else
              return false
            end
          end
          org_admin = OrganizationAdmin.where(organization_id: organization.id, user_id: resource.id).first

          if org_admin.present?
            return true
          else
            return false
          end
        else
          return false
        end
      end

      def is_admin_user?(resource)
        return resource.role == 'admin'
      end
    end
  end
end

Warden::Strategies.add(:database_authenticatable, Devise::Strategies::DatabaseAuthenticatable)
