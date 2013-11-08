# Copyright 2011 Dell, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

service node[:quantum][:platform][:service] do
  supports :status => true, :restart => true, :reload => true
  action :nothing
end

# prepare plugin variable
case node[:quantum][:networking_plugin]
when "openvswitch"
  plugin_packages = node[:quantum][:platform][:plugins]["openvswitch"]
  plugin_cfg_path = "/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini"
  physnet = node[:quantum][:networking_mode] == 'gre' ? "br-tunnel" : "br-fixed"
  interface_driver = "quantum.agent.linux.interface.OVSInterfaceDriver"
when "linuxbridge"
  plugin_packages = node[:quantum][:platform][:plugins]["linuxbridge"]
  plugin_cfg_path = "/etc/quantum/plugins/linuxbridge/linuxbridge_conf.ini"
  physnet = (node[:crowbar_wall][:network][:nets][:nova_fixed].first rescue nil)
  interface_driver = "quantum.agent.linux.interface.BridgeInterfaceDriver"
end

unless node[:quantum][:use_gitrepo]

  # install server package
  package node[:quantum][:platform][:server] do
    # stop server if package installed or updated
    notifies :stop, "service[#{node[:quantum][:platform][:service]}]", :immediately
  end.run_action(:install)

  # install plugin packages
  (plugin_packages||[]).each do |pkg|
    package pkg
  end

  file "/etc/default/quantum-server" do
    action :delete
    not_if { node[:platform] == "suse" }
    notifies :restart, "service[#{node[:quantum][:platform][:service]}]"
  end

  template "/etc/sysconfig/quantum" do
    source "suse.sysconfig.quantum.erb"
    owner "root"
    group "root"
    mode 0640
    variables(
        :plugin_config_file => plugin_cfg_path
    )
    only_if { node[:platform] == "suse" }
    notifies :restart, "service[#{node[:quantum][:platform][:service]}]"
  end

else

  quantum_path = "/opt/quantum"
  venv_path = node[:quantum][:use_virtualenv] ? "#{quantum_path}/.venv" : nil

  link_service "quantum-server" do
    virtualenv venv_path
    bin_name "quantum-server --config-dir /etc/quantum/"
  end

end

include_recipe "quantum::database"
include_recipe "quantum::api_register"

env_filter = " AND keystone_config_environment:keystone-config-#{node[:quantum][:keystone_instance]}"
keystones = search(:node, "recipes:keystone\\:\\:server#{env_filter}") || []
if keystones.length > 0
  keystone = keystones[0]
  keystone = node if keystone.name == node.name
else
  keystone = node
end

keystone_settings = {
  :host => keystone[:fqdn],
  :protocol => keystone["keystone"]["api"]["protocol"],
  :service_port => keystone["keystone"]["api"]["service_port"],
  :admin_port => keystone["keystone"]["api"]["admin_port"],
  :service_tenant => keystone["keystone"]["service"]["tenant"],
  :service_user => node["quantum"]["service_user"],
  :service_password => node["quantum"]["service_password"]
}

env_filter = " AND rabbitmq_config_environment:rabbitmq-config-#{node[:quantum][:rabbitmq_instance]}"
rabbits = search(:node, "roles:rabbitmq#{env_filter}") || []
if rabbits.length > 0
  rabbit = rabbits[0]
  rabbit = node if rabbit.name == node.name
else
  rabbit = node
end
rabbit_address = Chef::Recipe::Barclamp::Inventory.get_network_by_type(rabbit, "admin").address
Chef::Log.info("Rabbit server found at #{rabbit_address}")
rabbit_settings = {
    :address => rabbit_address,
    :port => rabbit[:rabbitmq][:port],
    :user => rabbit[:rabbitmq][:user],
    :password => rabbit[:rabbitmq][:password],
    :vhost => rabbit[:rabbitmq][:vhost]
}

vlan = {
    :start => node[:network][:networks][:nova_fixed][:vlan],
    :end => node[:network][:networks][:nova_fixed][:vlan] + 2000
}

template "/etc/quantum/quantum.conf" do
  cookbook "quantum"
  source "quantum.conf.erb"
  mode "0640"
  owner node[:quantum][:platform][:user]
  variables(
    :debug => node[:quantum][:debug],
    :verbose => node[:quantum][:verbose],
    :sql_connection => node[:quantum][:db][:sql_connection],
    :sql_idle_timeout => node[:quantum][:sql][:idle_timeout],
    :sql_min_pool_size => node[:quantum][:sql][:min_pool_size],
    :sql_max_pool_size => node[:quantum][:sql][:max_pool_size],
    :sql_pool_timeout => node[:quantum][:sql][:pool_timeout],
    :debug => node[:quantum][:debug],
    :verbose => node[:quantum][:verbose],
    :service_port => node[:quantum][:api][:service_port], # Compute port
    :service_host => node[:quantum][:api][:service_host],
    :use_syslog => node[:quantum][:use_syslog],
    :ssl_enabled => node[:quantum][:api][:protocol] == 'https',
    :ssl_cert_file => node[:quantum][:ssl][:certfile],
    :ssl_key_file => node[:quantum][:ssl][:keyfile],
    :ssl_cert_required => node[:quantum][:ssl][:cert_required],
    :ssl_ca_file => node[:quantum][:ssl][:ca_certs],
    :networking_mode => node[:quantum][:networking_mode],
    :networking_plugin => node[:quantum][:networking_plugin],
    :rootwrap_bin =>  node[:quantum][:rootwrap],
    :quantum_server => true,
    :keystone => keystone_settings,
    :rabbit => rabbit_settings,
    :vlan => vlan,
    :per_tenant_vlan => (node[:quantum][:networking_mode] == 'vlan' ? true : false),
    :physnet => physnet,
    :interface_driver => interface_driver
  )
end

template "/etc/quantum/api-paste.ini" do
  source "api-paste.ini.erb"
  owner node[:quantum][:platform][:user]
  group "root"
  mode "0640"
  variables(
      :keystone => keystone_settings
  )
end

service node[:quantum][:platform][:service] do
  supports :status => true, :restart => true, :reload => true
  subscribes :restart, "template[/etc/quantum/api-paste.ini]", :immediately
  subscribes :restart, "template[/etc/quantum/quantum.conf]", :immediately
end.run_action(:start)

include_recipe "quantum::post_install_conf"

node[:quantum][:monitor] = {} if node[:quantum][:monitor].nil?
node[:quantum][:monitor][:svcs] = [] if node[:quantum][:monitor][:svcs].nil?
node[:quantum][:monitor][:svcs] << ["quantum"] if node[:quantum][:monitor][:svcs].empty?
node.save
