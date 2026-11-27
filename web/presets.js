// Presets: a filter and a look for a common setup, in one pick. A preset says
// what to trace, which layers the combined view shows, and which devices and
// processes stay in the diagram on view. views are the views it fits: a preset
// that hides the bridges is of no use in the bridge view. Everything a preset
// sets can be changed afterwards.

const ALL = ['l1', 'l2', 'l3'];
const isBridge = (d) => d.kind === 'bridge';
const isPort = (d) => !!d.master;
const isLoopback = (d) => d.kind === 'loopback';

export const PRESETS = [
  {
    id: 'all', views: ['l3', 'l2', 'l1', 'all'], label: 'Everything',
    about: 'All traffic, all layers, every device and process.',
    filter: {}, layers: ALL, device: () => true, procs: true,
  },
  {
    id: 'local', views: ['l3', 'l1', 'all'], label: 'Local processes',
    about: 'IPv4 traffic of the processes of this machine: the IP hooks, without bridges and their ports.',
    filter: { protos: ['ip'] }, layers: ['l3'], device: (d) => !isBridge(d) && !isPort(d), procs: true,
  },
  {
    id: 'router', views: ['l3', 'l1', 'all'], label: 'Router',
    about: 'IPv4 packets that the machine forwards: the device and IP hooks, without loopback, bridges, and processes.',
    filter: { protos: ['ip'] }, layers: ['l1', 'l3'], device: (d) => !isBridge(d) && !isPort(d) && !isLoopback(d), procs: false,
  },
  {
    id: 'containers', views: ['l3', 'l2', 'l1', 'all'], label: 'Container host',
    about: 'ARP and IPv4 traffic of containers behind a bridge: all layers, without loopback.',
    filter: { protos: ['arp', 'ip'] }, layers: ALL, device: (d) => !isLoopback(d), procs: true,
  },
  {
    id: 'bridge', views: ['l2', 'l1', 'all'], label: 'Bridge only',
    about: 'Frames that a bridge switches: the device and bridge hooks, with the bridges and their ports only.',
    filter: { protos: ['arp', 'ip', 'other'] }, layers: ['l1', 'l2'], device: (d) => isBridge(d) || isPort(d), procs: false,
  },
];
