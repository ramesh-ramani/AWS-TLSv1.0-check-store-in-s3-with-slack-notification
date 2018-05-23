import boto3
import nmap
import slackweb

##Below Lines let's the user input an instance Name in a File##

cloudwatch=boto3.client('cloudwatch')

h_dict={}
i_dict={}
lb_arn_lst=list()
lb_name_lst=list()
#t = open("TLS_SEC_output.txt","+w")
b = open("TLS_Build_output.txt","+w")
#l_lst=list()
#e_lst=list()
sum_sec_usw2=0
sum_sec_euc1=0
sum_build_usw2=0
sum_build_euc1=0
sum_riq_usw2=0
sum_riq_euc1=0
sum_iqc_usw2=0
sum_iqc_euc1=0
sum_ecpprod_usw2=0
sum_ecpprod_euc1=0
sum_ecpstaging_usw2=0
sum_ecpstaging_euc1=0


def TLS(session,account):
  print(account)
  t = open("TLS_SEC_output.txt","+w")
  g_dict={}
  f_dict={}
  l_lst=list()
  e_lst=list()
  elbList = session.client('elbv2')
  elbList_1 = session.client('elb')
  ec2 = session.resource('ec2')
  bals = elbList.describe_load_balancers()
  bals1 = elbList_1.describe_load_balancers()
  for i in bals['LoadBalancers']:
      f_dict[i['LoadBalancerName']]=i['DNSName']
         
  for i in bals1['LoadBalancerDescriptions']:
      g_dict[i['LoadBalancerName']]=i['DNSName']

  ##Connect to ELB and check if there's an output for openssl connect for tlsv1 and write output to internal-elbs-with-tlsv1.txt or unreachable-internal-lbs.txt##
  nm = nmap.PortScanner()
  dict_2={} 
  for k,v in g_dict.items(): 
  #    print(v)
      dict=(nm.scan(v, '443', '--script ssl-enum-ciphers'))
      dict_1=dict['scan']
      if len(dict_1) !=1: continue 
      else:
          for i in dict_1:
              var=i
              dict_2=dict_1[var]
              break
      for i,j in dict_2['tcp'].items():
          if "script" not in j: break
          for r,s in j['script'].items():
              if "TLSv1.0" in s:
                 print(v,"support TLSv1.0")
                 l_lst.append(v)
                 break
          break
  print(l_lst)
  for k,v in f_dict.items():
  #    print(v)
      dict=(nm.scan(v, '443', '-script ssl-enum-ciphers'))
      dict_1=dict['scan']
      if len(dict_1) !=1: continue
      else:
          for i in dict_1:
              var=i
              dict_2=dict_1[var]
              break
      for i,j in dict_2['tcp'].items():
          if "script" not in j: break
          for r,s in j['script'].items():
              if "TLSv1.0" in s:
                 print(v,"support TLSv1.0")
                 e_lst.append(v)
                 break
          break
  print(e_lst)


  ##Data written to a File##

  for i in e_lst+l_lst:
      t.write(i+'\n')
  t.close()


def <account name as mentioned in profile>():
         #sum=0
         global sum_sec_usw2
         session = boto3.Session(profile_name=<profile name>,region_name=<region code>)
         TLS(session,<profile name>)
         f_handle=open('TLS_SEC_output.txt','r')
         for i in f_handle:
             sum_sec_usw2=sum_sec_usw2+1
if __name__ == '__main__':
    <account name as mentioned in profile>()

session = boto3.Session(profile_name=<profile name>,region_name='<region code>)
s3=session.client('s3')
s3.upload_file('/Users/rramani/python_scripts/TLS_SEC_output.txt','tlsv1.0-check','TLS-Profile.txt')


slack = slackweb.Slack(url="")
slack.notify(text="*Summary of TLSv1.0 Check Results*")
slack.notify(text="=============================")

if sum_sec_usw2==0:
   slack.notify(text="Number of URLs that support TLSv1.0 in the '<profile name>' account = 0")
else:
   slack.notify(text="Number of URLs that support TLSv1.0 in the `<profile name>`account = "+str(sum_sec_usw2))
slack.notify(text="=============================")
slack.notify(text="Please goto the corresponding URL File for each account in `` to view the details")

