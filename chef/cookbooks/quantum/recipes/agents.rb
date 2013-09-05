# recipe must be call from nova-compute node to install agents
quantum = search(:node, "roles:quantum-server AND quantum_config_environment:quantum-config-#{node[:nova][:quantum_instance]}").first

puts ">>> QUANTUM: #{quantum.name}"
puts ">>> COMPUTE: #{node.name}"

# install agents

unless quantum[:quantum][:use_gitrepo]
  agents = node[:quantum][:platform][:agents]
  agents.each do |name, agent|
    (agent[:packages] || []).each do |pkg|
      service name do
        supports :status => true, :restart => true, :reload => true
        action :nothing
      end
      package pkg do
        action :install
        notifies :stop, "service[#{name}]", :immediately
      end.run_action(:install)
    end
    (agent[:commands] || {}).each do |cmd,condition|
      execute cmd do
        not_if condition
      end
    end
  end
else
  #TODO: install from PFS
end

node[:quantum] ||= Mash.new
if not node[:quantum].has_key?("rootwrap")
  unless quantum[:quantum][:use_gitrepo]
    node.set[:quantum][:rootwrap] = "/usr/bin/quantum-rootwrap"
  else
    node.set[:quantum][:rootwrap] = "/usr/local/bin/quantum-rootwrap"
  end
end

# Update path to quantum-rootwrap in case the path above is wrong
ruby_block "Find quantum rootwrap" do
  block do
    found = false
    ENV['PATH'].split(':').each do |p|
      f = File.join(p,"quantum-rootwrap")
      next unless File.executable?(f)
      node.set[:quantum][:rootwrap] = f
      node.save
      found = true
      break
    end
    raise("Could not find quantum rootwrap binary!") unless found
  end
end

template node[:quantum][:platform][:quantum_rootwrap_sudo_template] do
  cookbook "quantum"
  source "quantum-rootwrap.erb"
  mode 0440
  variables(:user => quantum[:quantum][:platform][:user],
            :binary => node[:quantum][:rootwrap])
end

case quantum[:quantum][:networking_plugin]
  when "openvswitch"

    interface_driver = "quantum.agent.linux.interface.OVSInterfaceDriver"
    physnet = quantum[:quantum][:networking_mode] == 'gre' ? "br-tunnel" : "br-fixed"
    external_network_bridge = "br-public"

    service "openvswitch-switch" do
      supports :status => true, :restart => true
      action [ :enable, :start ]
    end

    bash "Start openvswitch-switch service" do
      code "service openvswitch-switch start"
      only_if "service openvswitch-switch status |grep -q 'is not running'"
    end

    # We always need br-int.  Quantum uses this bridge internally.
    execute "create_int_br" do
      command "ovs-vsctl add-br br-int"
      not_if "ovs-vsctl list-br | grep -q br-int"
    end

    # Make sure br-int is always up.
    ruby_block "Bring up the internal bridge" do
      block do
        ::Nic.new('br-int').up
      end
    end

    # Create the bridges Quantum needs.
    # Usurp config as needed.
    [ [ "nova_fixed", "fixed" ],
      [ "os_sdn", "tunnel" ],
      [ "public", "public"] ].each do |net|
      bound_if = (node[:crowbar_wall][:network][:nets][net[0]].last rescue nil)
      next unless bound_if
      name = "br-#{net[1]}"
      execute "Quantum: create #{name}" do
        command "ovs-vsctl add-br #{name}; ip link set #{name} up"
        not_if "ovs-vsctl list-br |grep -q #{name}"
      end
      next if net[1] == "tunnel"
      execute "Quantum: add #{bound_if} to #{name}" do
        command "ovs-vsctl del-port #{name} #{bound_if} ; ovs-vsctl add-port #{name} #{bound_if}"
        not_if "ovs-dpctl show system@#{name} | grep -q #{bound_if}"
      end
      ruby_block "Have #{name} usurp config from #{bound_if}" do
        block do
          target = ::Nic.new(name)
          res = target.usurp(bound_if)
          Chef::Log.info("#{name} usurped #{res[0].join(", ")} addresses from #{bound_if}") unless res[0].empty?
          Chef::Log.info("#{name} usurped #{res[1].join(", ")} routes from #{bound_if}") unless res[1].empty?
        end
      end
    end

  when "linuxbridge"
    interface_driver = "quantum.agent.linux.interface.BridgeInterfaceDriver"
    physnet = (node[:crowbar_wall][:network][:nets][:nova_fixed].first rescue nil)
    external_network_bridge = ""
end

nova = search(:node, "roles:nova-multi-controller").first || node
nova = node if nova.name == node.name

metadata_settings = {
  :host => Chef::Recipe::Barclamp::Inventory.get_network_by_type(nova, "admin").address,
  :port => "8775",
  :secret => (nova[:nova][:quantum_metadata_proxy_shared_secret] rescue '')
}

env_filter = " AND keystone_config_environment:keystone-config-#{quantum[:quantum][:keystone_instance]}"
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
    :service_user => quantum["quantum"]["service_user"],
    :service_password => quantum["quantum"]["service_password"]
}

# configure OpenVSwitch agent
link "/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini" do
  to "/etc/quantum/quantum.conf"
end

# configure L3 agent
template "/etc/quantum/l3_agent.ini" do
  cookbook "quantum"
  source "l3_agent.ini.erb"
  owner node[:quantum][:platform][:user]
  group "root"
  mode "0640"
  variables(
      :debug => quantum[:quantum][:debug],
      :verbose => quantum[:quantum][:verbose],
      :interface_driver => interface_driver,
      :use_namespaces => "True",
      :handle_internal_only_routers => "True",
      :metadata_port => 9697,
      :send_arp_for_ha => 3,
      :periodic_interval => 40,
      :periodic_fuzzy_delay => 5
  )
  notifies :restart, "service[quantum-l3-agent]", :immediately
end

# configure DHCP agent
template "/etc/quantum/dhcp_agent.ini" do
  cookbook "quantum"
  source "dhcp_agent.ini.erb"
  owner quantum[:quantum][:platform][:user]
  group "root"
  mode "0640"
  variables(
      :debug => quantum[:quantum][:debug],
      :verbose => quantum[:quantum][:verbose],
      :interface_driver => interface_driver,
      :use_namespaces => "True",
      :resync_interval => 5,
      :dhcp_driver => "quantum.agent.linux.dhcp.Dnsmasq",
      :dhcp_domain => quantum[:quantum][:dhcp_domain],
      :enable_isolated_metadata => "True",
      :enable_metadata_network => "False",
      :nameservers => quantum[:dns][:forwarders].join(" ")
  )
  notifies :restart, "service[quantum-dhcp-agent]", :immediately
end

# configure METADATA agent
template "/etc/quantum/metadata_agent.ini" do
  cookbook "quantum"
  source "metadata_agent.ini.erb"
  owner node[:quantum][:platform][:user]
  group "root"
  mode "0640"
  variables(
      :debug => quantum[:quantum][:debug],
      :verbose => quantum[:quantum][:verbose],
      :keystone => keystone_settings,
      :nova_metadata_host => metadata_host,
      :nova_metadata_port => metadata_port,
      :metadata_proxy_shared_secret => metadata_proxy_shared_secret
  )
  notifies :restart, "service[quantum-metadata-agent]", :immediately
end

vlan = {
    :start => node[:network][:networks][:nova_fixed][:vlan],
    :end => node[:network][:networks][:nova_fixed][:vlan] + 2000
}

env_filter = " AND rabbitmq_config_environment:rabbitmq-config-#{quantum[:quantum][:rabbitmq_instance]}"
rabbits = search(:node, "roles:rabbitmq-server#{env_filter}") || []
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

# configure Quantum
template "/etc/quantum/api-paste.ini" do
  cookbook "quantum"
  source "api-paste.ini.erb"
  owner node[:quantum][:platform][:user]
  group "root"
  mode "0640"
  variables(
      :keystone => keystone_settings
  )
  notifies :restart, "service[quantum-l3-agent]", :immediately
  notifies :restart, "service[quantum-dhcp-agent]", :immediately
  notifies :restart, "service[quantum-metadata-agent]", :immediately
end
template "/etc/quantum/quantum.conf" do
  cookbook "quantum"
  source "quantum.conf.erb"
  mode "0640"
  owner node[:quantum][:platform][:user]
  variables(
      :sql_connection => quantum[:quantum][:db][:sql_connection],
      :sql_idle_timeout => quantum[:quantum][:sql][:idle_timeout],
      :sql_min_pool_size => quantum[:quantum][:sql][:min_pool_size],
      :sql_max_pool_size => quantum[:quantum][:sql][:max_pool_size],
      :sql_pool_timeout => quantum[:quantum][:sql][:pool_timeout],
      :debug => quantum[:quantum][:debug],
      :verbose => quantum[:quantum][:verbose],
      :service_port => quantum[:quantum][:api][:service_port], # Compute port
      :service_host => quantum[:quantum][:api][:service_host],
      :use_syslog => quantum[:quantum][:use_syslog],
      :networking_mode => quantum[:quantum][:networking_mode],
      :networking_plugin => quantum[:quantum][:networking_plugin],
      :rootwrap_bin =>  node[:quantum][:rootwrap],
      :quantum_server => false,
      :rabbit => rabbit_settings,
      :vlan => vlan,
      :per_tenant_vlan => (quantum[:quantum][:networking_mode] == 'vlan' ? true : false),
      :physnet => physnet,
      :interface_driver => interface_driver,
      :external_network_bridge => external_network_bridge,
      :metadata => metadata_settings
  )
  # TODO: return this if really needed
  notifies :restart, "service[quantum-l3-agent]", :immediately
  notifies :restart, "service[quantum-dhcp-agent]", :immediately
  notifies :restart, "service[quantum-metadata-agent]", :immediately
  notifies :restart, "service[quantum-plugin-openvswitch-agent]", :immediately
end
