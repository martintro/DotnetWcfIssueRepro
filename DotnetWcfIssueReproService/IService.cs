using System.ServiceModel;

namespace DotnetWcfIssueReproService
{
    [ServiceContract]
    public interface IService
    {
        [OperationContract]
        string GetData(int value);
    }
}
